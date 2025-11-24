/*
 * Copyright 2022 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// DNS Filter
//
// IMPORTANT: HOSTENT structures in BLOB format use RELATIVE POINTERS (offsets)
//            not absolute pointers. All pointer-typed fields in HOSTENT contain
//            offset values from the HOSTENT base address. Consumer code must
//            convert these offsets to absolute pointers using ABS_PTR before
//            dereferencing. This is required by Windows BLOB specification for
//            relocatable data structures.
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include <oleauto.h>
#include <SvcGuid.h>
#include <windns.h>
#include "common/my_wsa.h"
#include "common/netfw.h"
#include "common/map.h"
#include "wsa_defs.h"
#include "dnsapi_defs.h"
#include "common/pattern.h"
#include "common/str_util.h"
#include "core/drv/api_defs.h"
#include "core/drv/verify.h"


//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------


static int WSA_WSALookupServiceBeginW(
    LPWSAQUERYSETW  lpqsRestrictions,
    DWORD           dwControlFlags,
    LPHANDLE        lphLookup);

static int WSA_WSALookupServiceNextW(
    HANDLE          hLookup,
    DWORD           dwControlFlags,
    LPDWORD         lpdwBufferLength,
    LPWSAQUERYSETW  lpqsResults);

static int WSA_WSALookupServiceEnd(HANDLE hLookup);


BOOLEAN WSA_GetIP(const short* addr, int addrlen, IP_ADDRESS* pIP);
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);


//---------------------------------------------------------------------------
// DnsApi Functions
//---------------------------------------------------------------------------


static DNS_STATUS DNSAPI_DnsQuery_W(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQuery_A(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQuery_UTF8(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle);

static DNS_STATUS DNSAPI_DnsQueryRaw(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_MESSAGE_BUFFER* ppMsgBuf,
    PVOID*          pReserved);


//---------------------------------------------------------------------------


static P_WSALookupServiceBeginW __sys_WSALookupServiceBeginW = NULL;
static P_WSALookupServiceNextW __sys_WSALookupServiceNextW = NULL;
static P_WSALookupServiceEnd __sys_WSALookupServiceEnd = NULL;

static P_DnsQuery_W __sys_DnsQuery_W = NULL;
static P_DnsQuery_A __sys_DnsQuery_A = NULL;
static P_DnsQuery_UTF8 __sys_DnsQuery_UTF8 = NULL;
static P_DnsQueryEx __sys_DnsQueryEx = NULL;
static P_DnsQueryRaw __sys_DnsQueryRaw = NULL;


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


extern POOL* Dll_Pool;

static LIST       WSA_FilterList;
static BOOLEAN    WSA_FilterEnabled = FALSE;

typedef struct _IP_ENTRY
{
    LIST_ELEM list_elem;

    USHORT Type;
    IP_ADDRESS IP;
} IP_ENTRY;

typedef struct _WSA_LOOKUP {
    LIST* pEntries;          // THREAD SAFETY: Read-only after initialization; safe for concurrent reads
    BOOLEAN NoMore;
    WCHAR* DomainName;       // Request Domain
    GUID* ServiceClassId;    // Request Class ID
    DWORD Namespace;         // Request Namespace
    BOOLEAN Filtered;        // Filter flag
} WSA_LOOKUP;

static HASH_MAP   WSA_LookupMap;

static BOOLEAN    WSA_DnsTraceFlag = FALSE;


//---------------------------------------------------------------------------
// WSA_GetLookup
//---------------------------------------------------------------------------


_FX WSA_LOOKUP* WSA_GetLookup(HANDLE h, BOOLEAN bCanAdd)
{
    WSA_LOOKUP* pLookup = (WSA_LOOKUP*)map_get(&WSA_LookupMap, h);
    if (pLookup == NULL && bCanAdd) {
        pLookup = (WSA_LOOKUP*)map_insert(&WSA_LookupMap, h, NULL, sizeof(WSA_LOOKUP));
        if (pLookup) {
            pLookup->pEntries = NULL;
            pLookup->NoMore = FALSE;
            pLookup->DomainName = NULL;
            pLookup->ServiceClassId = NULL;
            pLookup->Filtered = FALSE;
        }
    }
    return pLookup;
}

//---------------------------------------------------------------------------
// WSA_IsIPv6Query
//---------------------------------------------------------------------------

_FX BOOLEAN WSA_IsIPv6Query(LPGUID lpServiceClassId)
{
    if (lpServiceClassId) {
        if (memcmp(lpServiceClassId, &(GUID)SVCID_DNS_TYPE_AAAA, sizeof(GUID)) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// Helper macros for alignment and relative pointers
//---------------------------------------------------------------------------

// Static assertion to ensure pointer size matches uintptr_t (required for offset storage)
// This validates our assumption that offsets can be safely stored in pointer-typed fields
#if defined(_WIN64)
static_assert(sizeof(void*) == sizeof(uintptr_t) && sizeof(void*) == 8, "64-bit pointer size mismatch");
#else
static_assert(sizeof(void*) == sizeof(uintptr_t) && sizeof(void*) == 4, "32-bit pointer size mismatch");
#endif

// Align pointer up to specified boundary (must be power of 2)
#define ALIGN_UP(ptr, align) (BYTE*)((((UINT_PTR)(ptr)) + ((align)-1)) & ~((UINT_PTR)((align)-1)))

// Relative pointer helpers for HOSTENT blob
// Windows BLOB format uses offsets (not absolute pointers) from the base address
// This is required for the HOSTENT structure to be relocatable in memory
#define REL_OFFSET(base, ptr) ((uintptr_t)((BYTE*)(ptr) - (BYTE*)(base)))
#define ABS_PTR(base, rel)    ((void*)(((BYTE*)(base)) + (uintptr_t)(rel)))

// Extract offset value from a pointer-typed field that actually contains a relative offset
// Use this when reading HOSTENT blob relative pointers stored in pointer-typed fields
// NOTE: This extracts the stored offset value, not a pointer - do not dereference the result
static inline uintptr_t GET_REL_FROM_PTR(void* p) {
    return (uintptr_t)(p);
}

// Debug buffer bounds checking (only in debug builds)
#ifdef _DEBUG
#define CHECK_BUFFER_SPACE(ptr, size, end) \
    do { if ((BYTE*)(ptr) + (size) > (BYTE*)(end)) { \
        SetLastError(WSAEFAULT); \
        return FALSE; \
    } } while(0)
#else
#define CHECK_BUFFER_SPACE(ptr, size, end) ((void)0)
#endif

//---------------------------------------------------------------------------
// WSA_FillResponseStructure
//
// Builds a complete WSAQUERYSETW structure with DNS results in a single buffer.
// Memory layout: WSAQUERYSETW | ServiceInstanceName | QueryString | CSADDR_INFO[] | 
//                SOCKADDR[] | BLOB | HOSTENT | h_name | h_aliases | h_addr_list | IPs
//
// IMPORTANT: The HOSTENT structure uses RELATIVE pointers (offsets from hostentBase)
//            as per Windows BLOB specification for relocatable data structures.
//
// Encoding: Domain names are converted from WCHAR to ANSI (CP_ACP) for HOSTENT
//           compatibility with Windows host resolution APIs.
//
// Thread Safety: This function reads from shared pLookup->pEntries list but does
//                not modify it. Concurrent calls are safe if the list is immutable
//                after initialization. Each call writes to caller-provided buffer.
//---------------------------------------------------------------------------

_FX BOOLEAN WSA_FillResponseStructure(
    WSA_LOOKUP* pLookup,
    LPWSAQUERYSETW lpqsResults,
    LPDWORD lpdwBufferLength)
{
    // Validate input parameters
    if (!pLookup || !pLookup->pEntries || !lpqsResults || !lpdwBufferLength)
        return FALSE;

    if (!pLookup->DomainName)
        return FALSE;

    BOOLEAN isIPv6Query = WSA_IsIPv6Query(pLookup->ServiceClassId);

    // Cache string length to avoid repeated wcslen calls
    SIZE_T domainChars = wcslen(pLookup->DomainName);
    
    // Convert domain name to narrow string (ANSI - CP_ACP) for HOSTENT
    // NOTE: Using CP_ACP encoding as Windows HOSTENT APIs expect ANSI strings
    // Pre-compute converted length for accurate size calculation
    int hostNameBytesNeeded = WideCharToMultiByte(CP_ACP, 0, pLookup->DomainName, (int)(domainChars + 1), NULL, 0, NULL, NULL);
    if (hostNameBytesNeeded <= 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Calc buffer size needed
    SIZE_T neededSize = sizeof(WSAQUERYSETW);
    SIZE_T domainNameLen = (domainChars + 1) * sizeof(WCHAR);
    neededSize += domainNameLen;  // for lpszServiceInstanceName
    neededSize += domainNameLen;  // for lpszQueryString

    // Calc IP size
    SIZE_T ipCount = 0;
    IP_ENTRY* entry;

    // Filter IP by type
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type == AF_INET6) ||
            (!isIPv6Query && entry->Type == AF_INET)) {
            ipCount++;
        }
    }

    if (ipCount == 0) {
        SetLastError(WSA_E_NO_MORE);
        return FALSE;
    }

    // Defensive: ensure ipCount fits in DWORD before casting (extremely large rule lists)
    if (ipCount > 0xFFFFFFFFUL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SIZE_T csaddrSize = (SIZE_T)ipCount * sizeof(CSADDR_INFO);
    neededSize += csaddrSize;

    SIZE_T sockaddrSize = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type == AF_INET6) ||
            (!isIPv6Query && entry->Type == AF_INET)) {
            if (entry->Type == AF_INET)
                sockaddrSize += sizeof(SOCKADDR_IN) * 2;
            else if (entry->Type == AF_INET6)
                sockaddrSize += sizeof(SOCKADDR_IN6_LH) * 2;
        }
    }
    neededSize += sockaddrSize;

    // Add BLOB size for HOSTENT structure
    // NOTE: Windows BLOB format requires relative offsets (not absolute pointers) for relocatable data
    // HOSTENT structure + converted domain name + h_aliases NULL + h_addr_list entries + final NULL + IP addresses
    SIZE_T addrSize = isIPv6Query ? 16 : 4;  // IPv6 or IPv4 address size
    SIZE_T blobSize = sizeof(HOSTENT) + 
                      (SIZE_T)hostNameBytesNeeded +                    // Narrow string (ANSI)
                      (sizeof(void*) - 1) +                             // Worst-case padding before h_aliases
                      sizeof(PCHAR) +                                   // h_aliases NULL terminator
                      (sizeof(void*) - 1) +                             // Worst-case padding before h_addr_list
                      (ipCount * sizeof(PCHAR)) + sizeof(PCHAR) +       // h_addr_list array + NULL terminator
                      (ipCount * addrSize);                             // actual IP addresses
    
    // Account for alignment padding before BLOB structure
    neededSize = (neededSize + (sizeof(void*) - 1)) & ~(sizeof(void*) - 1);
    neededSize += sizeof(BLOB) + blobSize;

    // Check for overflow (DWORD is 32-bit unsigned)
    if (neededSize > 0xFFFFFFFF) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Buffer not enough, return error
    if (*lpdwBufferLength < (DWORD)neededSize) {
        *lpdwBufferLength = (DWORD)neededSize;
        SetLastError(WSAEFAULT);
        return FALSE;
    }

    memset(lpqsResults, 0, sizeof(WSAQUERYSETW));

    lpqsResults->dwSize = sizeof(WSAQUERYSETW);
    lpqsResults->dwNameSpace = pLookup->Namespace;

    BYTE* currentPtr = (BYTE*)lpqsResults + sizeof(WSAQUERYSETW);
    
#ifdef _DEBUG
    // Debug: set buffer end for bounds checking
    BYTE* bufferEnd = (BYTE*)lpqsResults + *lpdwBufferLength;
#endif

    // Copy ServiceInstanceName (wide string)
    CHECK_BUFFER_SPACE(currentPtr, domainNameLen, bufferEnd);
    lpqsResults->lpszServiceInstanceName = (LPWSTR)currentPtr;
    wcscpy(lpqsResults->lpszServiceInstanceName, pLookup->DomainName);
    currentPtr += domainNameLen;

    // Copy QueryString (wide string)
    CHECK_BUFFER_SPACE(currentPtr, domainNameLen, bufferEnd);
    lpqsResults->lpszQueryString = (LPWSTR)currentPtr;
    wcscpy(lpqsResults->lpszQueryString, pLookup->DomainName);
    currentPtr += domainNameLen;

    // CSADDR_INFO array
    CHECK_BUFFER_SPACE(currentPtr, csaddrSize, bufferEnd);
    lpqsResults->dwNumberOfCsAddrs = (DWORD)ipCount;  // Safe: already verified ipCount fits in buffer
    lpqsResults->lpcsaBuffer = (PCSADDR_INFO)currentPtr;
    currentPtr += csaddrSize;

    SIZE_T i = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type != AF_INET6) ||
            (!isIPv6Query && entry->Type != AF_INET)) {
            continue;
        }

        PCSADDR_INFO csaInfo = &lpqsResults->lpcsaBuffer[i++];

        if (entry->Type == AF_INET) {
            CHECK_BUFFER_SPACE(currentPtr, sizeof(SOCKADDR_IN) * 2, bufferEnd);
            SOCKADDR_IN* remoteAddr = (SOCKADDR_IN*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN);
            memset(remoteAddr, 0, sizeof(SOCKADDR_IN));

            remoteAddr->sin_family = AF_INET;
            remoteAddr->sin_port = 0x3500;  // DNS port 53 in network byte order (big-endian)
            remoteAddr->sin_addr.S_un.S_addr = entry->IP.Data32[3];

            csaInfo->RemoteAddr.lpSockaddr = (LPSOCKADDR)remoteAddr;
            csaInfo->RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_IN);

            SOCKADDR_IN* localAddr = (SOCKADDR_IN*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN);
            memset(localAddr, 0, sizeof(SOCKADDR_IN));

            localAddr->sin_family = AF_INET;
            localAddr->sin_port = 0;
            localAddr->sin_addr.S_un.S_addr = 0;

            csaInfo->LocalAddr.lpSockaddr = (LPSOCKADDR)localAddr;
            csaInfo->LocalAddr.iSockaddrLength = sizeof(SOCKADDR_IN);


            csaInfo->iSocketType = SOCK_DGRAM;
            csaInfo->iProtocol = IPPROTO_UDP;
        }
        else if (entry->Type == AF_INET6) {
            CHECK_BUFFER_SPACE(currentPtr, sizeof(SOCKADDR_IN6_LH) * 2, bufferEnd);
            SOCKADDR_IN6_LH* remoteAddr = (SOCKADDR_IN6_LH*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN6_LH);
            memset(remoteAddr, 0, sizeof(SOCKADDR_IN6_LH));

            remoteAddr->sin6_family = AF_INET6;
            remoteAddr->sin6_port = 0x3500;  // DNS port 53 in network byte order (big-endian)
            memcpy(remoteAddr->sin6_addr.u.Byte, entry->IP.Data, 16);

            csaInfo->RemoteAddr.lpSockaddr = (LPSOCKADDR)remoteAddr;
            csaInfo->RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_IN6_LH);

            SOCKADDR_IN6_LH* localAddr = (SOCKADDR_IN6_LH*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN6_LH);
            memset(localAddr, 0, sizeof(SOCKADDR_IN6_LH));

            localAddr->sin6_family = AF_INET6;
            localAddr->sin6_port = 0;
            memset(localAddr->sin6_addr.u.Byte, 0, 16);

            csaInfo->LocalAddr.lpSockaddr = (LPSOCKADDR)localAddr;
            csaInfo->LocalAddr.iSockaddrLength = sizeof(SOCKADDR_IN6_LH);


            csaInfo->iSocketType = SOCK_RAW;
            // magic number returned by Windows
            csaInfo->iProtocol = 23;
        }
    }

    // Create BLOB with HOSTENT structure
    // Align currentPtr to pointer boundary before BLOB
    currentPtr = ALIGN_UP(currentPtr, sizeof(void*));
    
    CHECK_BUFFER_SPACE(currentPtr, sizeof(BLOB) + blobSize, bufferEnd);
    lpqsResults->lpBlob = (LPBLOB)currentPtr;
    memset(lpqsResults->lpBlob, 0, sizeof(BLOB));  // Zero BLOB structure
    currentPtr += sizeof(BLOB);

    lpqsResults->lpBlob->cbSize = (DWORD)blobSize;
    lpqsResults->lpBlob->pBlobData = currentPtr;

    HOSTENT* hostent = (HOSTENT*)currentPtr;
    memset(hostent, 0, sizeof(HOSTENT));  // Zero HOSTENT structure
    BYTE* hostentBase = currentPtr;
    currentPtr += sizeof(HOSTENT);

    // Set address type and length
    hostent->h_addrtype = isIPv6Query ? AF_INET6 : AF_INET;
    hostent->h_length = isIPv6Query ? 16 : 4;

    // Set h_name (relative offset - stored as pointer type but contains offset from base)
    // IMPORTANT: This is a RELATIVE OFFSET, not an absolute pointer
    hostent->h_name = (char*)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);
    
    // Convert WCHAR domain name to narrow ANSI string for HOSTENT
    int converted = WideCharToMultiByte(CP_ACP, 0, pLookup->DomainName, (int)(domainChars + 1), 
                                        (LPSTR)currentPtr, hostNameBytesNeeded, NULL, NULL);
    if (converted <= 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    currentPtr += converted;

    // Align for h_aliases pointer array
    currentPtr = ALIGN_UP(currentPtr, sizeof(void*));
    
    // Set h_aliases (relative offset to NULL-terminated pointer array)
    hostent->h_aliases = (char**)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);
    *(PCHAR*)currentPtr = 0;  // NULL terminator
    currentPtr += sizeof(PCHAR);

    // Align for h_addr_list pointer array
    currentPtr = ALIGN_UP(currentPtr, sizeof(void*));
    
    // Set h_addr_list (relative offset to pointer array)
    hostent->h_addr_list = (char**)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);
    PCHAR* addrList = (PCHAR*)currentPtr;
    currentPtr += (ipCount + 1) * sizeof(PCHAR);  // Array of pointers + NULL terminator

    // Fill IP addresses
    SIZE_T addrIdx = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type != AF_INET6) ||
            (!isIPv6Query && entry->Type != AF_INET)) {
            continue;
        }

        // Set address pointer (relative offset from hostentBase - stored as pointer but contains offset)
        addrList[addrIdx] = (char*)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);

        // Copy IP address
        if (isIPv6Query) {
            memcpy(currentPtr, entry->IP.Data, 16);
            currentPtr += 16;
        } else {
            *(DWORD*)currentPtr = entry->IP.Data32[3];
            currentPtr += 4;
        }
        addrIdx++;
    }
    addrList[addrIdx] = 0;  // NULL terminator

    // Final sanity check: ensure we didn't overrun the buffer (even in release builds)
    // This is a lightweight failsafe in case size calculations were wrong
    if ((BYTE*)currentPtr > ((BYTE*)lpqsResults + *lpdwBufferLength)) {
        SetLastError(WSAEFAULT);
        return FALSE;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// WSA_InitNetDnsFilter
//---------------------------------------------------------------------------


_FX BOOLEAN WSA_InitNetDnsFilter(HMODULE module)
{
    P_WSALookupServiceBeginW WSALookupServiceBeginW;
    P_WSALookupServiceNextW WSALookupServiceNextW;
    P_WSALookupServiceEnd WSALookupServiceEnd;

    List_Init(&WSA_FilterList);

    //
    // Load filter rules
    //

    WCHAR conf_buf[256];
    for (ULONG index = 0; ; ++index) {

        NTSTATUS status = SbieApi_QueryConf(
            NULL, L"NetworkDnsFilter", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        ULONG level = (ULONG)-1;
        WCHAR* value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, &level);
        if (!value)
            continue;

        WCHAR* domain_ip = wcschr(value, L':');
        if (domain_ip)
            *domain_ip++ = L'\0';

        PATTERN* pat = Pattern_Create(Dll_Pool, value, TRUE, level);

        if (domain_ip) {

            LIST* entries = (LIST*)Dll_Alloc(sizeof(LIST));
            List_Init(entries);

            BOOLEAN HasV6 = FALSE;

            const WCHAR* ip_value = domain_ip;
            ULONG ip_len = wcslen(domain_ip);
            for (const WCHAR* ip_end = ip_value + ip_len; ip_value < ip_end;) {
                const WCHAR* ip_str1;
                ULONG ip_len1;
                ip_value = SbieDll_GetTagValue(ip_value, ip_end, &ip_str1, &ip_len1, L';');

                IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                if (_inet_xton(ip_str1, ip_len1, &entry->IP, &entry->Type) == 1) {
                    if (entry->Type == AF_INET6)
                        HasV6 = TRUE;
                    List_Insert_After(entries, NULL, entry);
                }
            }

            if (!HasV6) {

                //
                // When there are no IPv6 entries, create IPv4-mapped IPv6 addresses
                // Format: ::ffff:a.b.c.d (RFC 4291 section 2.5.5.2)
                // This ensures IPv6 queries can resolve IPv4-only domains
                //

                for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(entries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
                    if (entry->Type != AF_INET)
                        continue;

                    IP_ENTRY* entry6 = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                    entry6->Type = AF_INET6;

                    // IPv4-mapped IPv6 address: first 80 bits zero, next 16 bits 0xFFFF, then IPv4 address
                    memset(entry6->IP.Data, 0, 10);
                    entry6->IP.Data[10] = 0xFF;
                    entry6->IP.Data[11] = 0xFF;
                    memcpy(&entry6->IP.Data[12], &entry->IP.Data32[3], 4);

                    List_Insert_After(entries, NULL, entry6);
                }
            }

            PVOID* aux = Pattern_Aux(pat);
            *aux = entries;
        }

        List_Insert_After(&WSA_FilterList, NULL, pat);
    }

    if (WSA_FilterList.count > 0) {

        WSA_FilterEnabled = TRUE;

        map_init(&WSA_LookupMap, Dll_Pool);

        __declspec(align(8)) SCertInfo CertInfo = { 0 };
        if (!NT_SUCCESS(SbieApi_QueryDrvInfo(-1, &CertInfo, sizeof(CertInfo))) || !(CertInfo.active && CertInfo.opt_net)) {

            const WCHAR* strings[] = { L"NetworkDnsFilter" , NULL };
            SbieApi_LogMsgExt(-1, 6009, strings);

            WSA_FilterEnabled = FALSE;
        }
    }

    //
    // Setup DNS hooks
    //

    WSALookupServiceBeginW = (P_WSALookupServiceBeginW)GetProcAddress(module, "WSALookupServiceBeginW");
    if (WSALookupServiceBeginW) {
        SBIEDLL_HOOK(WSA_, WSALookupServiceBeginW);
    }

    WSALookupServiceNextW = (P_WSALookupServiceNextW)GetProcAddress(module, "WSALookupServiceNextW");
    if (WSALookupServiceNextW) {
        SBIEDLL_HOOK(WSA_, WSALookupServiceNextW);
    }

    WSALookupServiceEnd = (P_WSALookupServiceEnd)GetProcAddress(module, "WSALookupServiceEnd");
    if (WSALookupServiceEnd) {
        SBIEDLL_HOOK(WSA_, WSALookupServiceEnd);
    }

    //
    // Setup DnsQuery hooks from dnsapi.dll
    // DnsQuery_W/A/UTF8 are available on Windows 2000+ (compatible with Win7/10/11)
    // DnsQueryEx is available on Windows Vista+ (compatible with Win7/10/11)
    // DnsQueryRaw availability varies by Windows version, checked via GetProcAddress
    // All functions use GetProcAddress to ensure compatibility across Windows versions
    //

    HMODULE dnsapi_module = GetModuleHandleW(L"dnsapi.dll");
    if (!dnsapi_module) {
        dnsapi_module = LoadLibraryW(L"dnsapi.dll");
    }

    if (dnsapi_module) {
        P_DnsQuery_W DnsQuery_W = (P_DnsQuery_W)GetProcAddress(dnsapi_module, "DnsQuery_W");
        if (DnsQuery_W) {
            SBIEDLL_HOOK(DNSAPI_, DnsQuery_W);
        }

        P_DnsQuery_A DnsQuery_A = (P_DnsQuery_A)GetProcAddress(dnsapi_module, "DnsQuery_A");
        if (DnsQuery_A) {
            SBIEDLL_HOOK(DNSAPI_, DnsQuery_A);
        }

        P_DnsQuery_UTF8 DnsQuery_UTF8 = (P_DnsQuery_UTF8)GetProcAddress(dnsapi_module, "DnsQuery_UTF8");
        if (DnsQuery_UTF8) {
            SBIEDLL_HOOK(DNSAPI_, DnsQuery_UTF8);
        }

        P_DnsQueryEx DnsQueryEx = (P_DnsQueryEx)GetProcAddress(dnsapi_module, "DnsQueryEx");
        if (DnsQueryEx) {
            SBIEDLL_HOOK(DNSAPI_, DnsQueryEx);
        }

        P_DnsQueryRaw DnsQueryRaw = (P_DnsQueryRaw)GetProcAddress(dnsapi_module, "DnsQueryRaw");
        if (DnsQueryRaw) {
            SBIEDLL_HOOK(DNSAPI_, DnsQueryRaw);
        }
    }

    // If there are any DnsTrace options set, then output this debug string
    WCHAR wsTraceOptions[4];
    if (SbieApi_QueryConf(NULL, L"DnsTrace", 0, wsTraceOptions, sizeof(wsTraceOptions)) == STATUS_SUCCESS && wsTraceOptions[0] != L'\0')
        WSA_DnsTraceFlag = TRUE;

    return TRUE;
}


//---------------------------------------------------------------------------
// WSA_WSALookupServiceBeginW
//---------------------------------------------------------------------------


_FX int WSA_WSALookupServiceBeginW(
    LPWSAQUERYSETW  lpqsRestrictions,
    DWORD           dwControlFlags,
    LPHANDLE        lphLookup)
{
    if (WSA_FilterEnabled && lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
        ULONG path_len = wcslen(lpqsRestrictions->lpszServiceInstanceName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, lpqsRestrictions->lpszServiceInstanceName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        PATTERN* found;
        if (Pattern_MatchPathList(path_lwr, path_len, &WSA_FilterList, NULL, NULL, NULL, &found) > 0) {
            HANDLE fakeHandle = (HANDLE)Dll_Alloc(sizeof(ULONG_PTR));
            if (!fakeHandle) {
                Dll_Free(path_lwr);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return SOCKET_ERROR;
            }

            *lphLookup = fakeHandle;

            WSA_LOOKUP* pLookup = WSA_GetLookup(fakeHandle, TRUE);
            if (pLookup) {
                pLookup->Filtered = TRUE;

                pLookup->DomainName = Dll_Alloc((path_len + 1) * sizeof(WCHAR));
                if (pLookup->DomainName) {
                    wcscpy_s(pLookup->DomainName, path_len + 1, lpqsRestrictions->lpszServiceInstanceName);
                }
                else {
                    SbieApi_Log(2205, L"NetworkDnsFilter: Failed to allocate domain name");
                }

                pLookup->Namespace = lpqsRestrictions->dwNameSpace;

                if (lpqsRestrictions->lpServiceClassId) {
                    pLookup->ServiceClassId = Dll_Alloc(sizeof(GUID));
                    if (pLookup->ServiceClassId) {
                        memcpy(pLookup->ServiceClassId, lpqsRestrictions->lpServiceClassId, sizeof(GUID));
                    }
                    else {
                        SbieApi_Log(2205, L"NetworkDnsFilter: Failed to allocate service class ID");
                    }
                }

                PVOID* aux = Pattern_Aux(found);
                if (*aux)
                    pLookup->pEntries = (LIST*)*aux;
                else
                    pLookup->NoMore = TRUE;
            }

            if (WSA_DnsTraceFlag) {
                WCHAR ClsId[64] = { 0 };
                if (lpqsRestrictions->lpServiceClassId) {
                    Sbie_snwprintf(ClsId, 64, L" (ClsId: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX)",
                        lpqsRestrictions->lpServiceClassId->Data1, lpqsRestrictions->lpServiceClassId->Data2, lpqsRestrictions->lpServiceClassId->Data3,
                        lpqsRestrictions->lpServiceClassId->Data4[0], lpqsRestrictions->lpServiceClassId->Data4[1], lpqsRestrictions->lpServiceClassId->Data4[2], lpqsRestrictions->lpServiceClassId->Data4[3],
                        lpqsRestrictions->lpServiceClassId->Data4[4], lpqsRestrictions->lpServiceClassId->Data4[5], lpqsRestrictions->lpServiceClassId->Data4[6], lpqsRestrictions->lpServiceClassId->Data4[7]);
                }

                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Request Intercepted: %s%s (NS: %d, Type: %s, Hdl: %p) - Using filtered response",
                    lpqsRestrictions->lpszServiceInstanceName, ClsId, lpqsRestrictions->dwNameSpace,
                    WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? L"IPv6" : L"IPv4", fakeHandle);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }

            Dll_Free(path_lwr);
            return NO_ERROR;
        }

        Dll_Free(path_lwr);
    }

    int ret = __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);

    if (WSA_DnsTraceFlag && lpqsRestrictions) {
        WCHAR ClsId[64] = { 0 };
        if (lpqsRestrictions->lpServiceClassId) {
            Sbie_snwprintf(ClsId, 64, L" (ClsId: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX)",
                lpqsRestrictions->lpServiceClassId->Data1, lpqsRestrictions->lpServiceClassId->Data2, lpqsRestrictions->lpServiceClassId->Data3,
                lpqsRestrictions->lpServiceClassId->Data4[0], lpqsRestrictions->lpServiceClassId->Data4[1], lpqsRestrictions->lpServiceClassId->Data4[2], lpqsRestrictions->lpServiceClassId->Data4[3],
                lpqsRestrictions->lpServiceClassId->Data4[4], lpqsRestrictions->lpServiceClassId->Data4[5], lpqsRestrictions->lpServiceClassId->Data4[6], lpqsRestrictions->lpServiceClassId->Data4[7]);
        }

        WCHAR msg[512];
        BOOLEAN isIPv6 = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId);
        Sbie_snwprintf(msg, 512, L"DNS Request Begin: %s%s, NS: %d, Type: %s, Hdl: %p, Err: %d)",
            lpqsRestrictions->lpszServiceInstanceName ? lpqsRestrictions->lpszServiceInstanceName : L"Unnamed",
            ClsId, lpqsRestrictions->dwNameSpace, isIPv6 ? L"IPv6" : L"IPv4",
            lphLookup ? *lphLookup : NULL, ret == SOCKET_ERROR ? GetLastError() : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return ret;
}


//---------------------------------------------------------------------------
// WSA_WSALookupServiceNextW
//---------------------------------------------------------------------------


_FX int WSA_WSALookupServiceNextW(
    HANDLE          hLookup,
    DWORD           dwControlFlags,
    LPDWORD         lpdwBufferLength,
    LPWSAQUERYSETW  lpqsResults)
{
    WSA_LOOKUP* pLookup = NULL;

    if (WSA_FilterEnabled) {
        pLookup = WSA_GetLookup(hLookup, FALSE);

        if (pLookup && pLookup->Filtered) {
            if (pLookup->NoMore || !pLookup->pEntries) {
                SetLastError(WSA_E_NO_MORE);
                return SOCKET_ERROR;
            }

            if (WSA_FillResponseStructure(pLookup, lpqsResults, lpdwBufferLength)) {
                pLookup->NoMore = TRUE;

                if (WSA_DnsTraceFlag) {
                    WCHAR msg[2048];
                    Sbie_snwprintf(msg, ARRAYSIZE(msg), L"DNS Filtered Response: %s (NS: %d, Type: %s, Hdl: %p)",
                        pLookup->DomainName, lpqsResults->dwNameSpace,
                        WSA_IsIPv6Query(pLookup->ServiceClassId) ? L"IPv6" : L"IPv4", hLookup);

                    for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; i++) {
                        IP_ADDRESS ip;
                        if (lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr &&
                            WSA_GetIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr,
                                lpqsResults->lpcsaBuffer[i].RemoteAddr.iSockaddrLength, &ip))
                            WSA_DumpIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family, &ip, msg);
                    }

                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }

                return NO_ERROR;
            }
            else {
                // GetLastError already set in WSA_FillResponseStructure
                return SOCKET_ERROR;
            }
        }

        if (pLookup && pLookup->NoMore) {

            SetLastError(WSA_E_NO_MORE);
            return SOCKET_ERROR;
        }
    }

    int ret = __sys_WSALookupServiceNextW(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);

    if (ret == NO_ERROR && pLookup && pLookup->pEntries) {

        //
        // This is a bit a simplified implementation, it assumes that all results are always of the same time
        // else it may truncate it early, also it can't return more results the have been found. 
        //

        if (lpqsResults->dwNumberOfCsAddrs > 0) {

            IP_ENTRY* entry = (IP_ENTRY*)List_Head(pLookup->pEntries);

            for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; i++) {

                USHORT af = lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family;
                for (; entry && entry->Type != af; entry = (IP_ENTRY*)List_Next(entry)); // skip to an entry of the right type
                if (!entry) { // no more entries clear remaining results
                    lpqsResults->dwNumberOfCsAddrs = i;
                    break;
                }

                if (af == AF_INET6)
                    memcpy(((SOCKADDR_IN6_LH*)lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr)->sin6_addr.u.Byte, entry->IP.Data, 16);
                else if (af == AF_INET)
                    ((SOCKADDR_IN*)lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr)->sin_addr.S_un.S_addr = entry->IP.Data32[3];

                entry = (IP_ENTRY*)List_Next(entry);
            }
        }

        if (lpqsResults->lpBlob != NULL) {

            IP_ENTRY* entry = (IP_ENTRY*)List_Head(pLookup->pEntries);

            HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
            if (hp->h_addrtype == AF_INET6 || hp->h_addrtype == AF_INET) {

                // Convert relative pointer to absolute using ABS_PTR helper
                // HOSTENT uses relative offsets (not absolute pointers) in BLOB format
                // Extract offset from pointer-typed field (stored as offset value, not real pointer)
                uintptr_t addrListOffset = GET_REL_FROM_PTR(hp->h_addr_list);
                PCHAR* addrArray = (PCHAR*)ABS_PTR(hp, addrListOffset);
                
                for (PCHAR* Addr = addrArray; *Addr; Addr++) {

                    for (; entry && entry->Type != hp->h_addrtype; entry = (IP_ENTRY*)List_Next(entry)); // skip to an entry of the right type
                    if (!entry) { // no more entries, clear remaining results
                        *Addr = 0;
                        break;  // No point continuing - all remaining addresses will be NULL
                    }

                    // Convert relative offset to absolute pointer (extract offset, then convert)
                    uintptr_t ipOffset = GET_REL_FROM_PTR(*Addr);
                    PCHAR ptr = (PCHAR)ABS_PTR(hp, ipOffset);
                    if (hp->h_addrtype == AF_INET6)
                        memcpy(ptr, entry->IP.Data, 16);
                    else if (hp->h_addrtype == AF_INET)
                        *(DWORD*)ptr = entry->IP.Data32[3];

                    entry = (IP_ENTRY*)List_Next(entry);
                }
            }
        }

        pLookup->NoMore = TRUE;
    }

    if (WSA_DnsTraceFlag && ret == NO_ERROR) {
        WCHAR msg[2048];
        Sbie_snwprintf(msg, ARRAYSIZE(msg), L"DNS Request Found: %s (NS: %d, Hdl: %p)",
            lpqsResults->lpszServiceInstanceName, lpqsResults->dwNameSpace, hLookup);

        for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; i++) {
            IP_ADDRESS ip;
            if (lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr &&
                WSA_GetIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr, 
                    lpqsResults->lpcsaBuffer[i].RemoteAddr.iSockaddrLength, &ip))
                WSA_DumpIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family, &ip, msg);
        }

        if (lpqsResults->lpBlob != NULL) {

            HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
            if (hp->h_addrtype != AF_INET6 && hp->h_addrtype != AF_INET) {
                WSA_DumpIP(hp->h_addrtype, NULL, msg);
            }
            else if (hp->h_addr_list) {
                // Convert relative pointer to absolute using ABS_PTR helper
                // Extract offset from pointer-typed field (stored as offset value, not real pointer)
                uintptr_t addrListOffset = GET_REL_FROM_PTR(hp->h_addr_list);
                PCHAR* addrArray = (PCHAR*)ABS_PTR(hp, addrListOffset);
                
                for (PCHAR* Addr = addrArray; *Addr; Addr++) {

                    // Convert relative offset to absolute pointer (extract offset, then convert)
                    uintptr_t ipOffset = GET_REL_FROM_PTR(*Addr);
                    PCHAR ptr = (PCHAR)ABS_PTR(hp, ipOffset);

                    IP_ADDRESS ip;
                    if (hp->h_addrtype == AF_INET6)
                        memcpy(ip.Data, ptr, 16);
                    else if (hp->h_addrtype == AF_INET)
                        ip.Data32[3] = *(DWORD*)ptr;
                    WSA_DumpIP(hp->h_addrtype, &ip, msg);
                }
            }
        }

        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return ret;
}


//---------------------------------------------------------------------------
// WSA_WSALookupServiceEnd
//---------------------------------------------------------------------------


_FX int WSA_WSALookupServiceEnd(HANDLE hLookup)
{
    if (WSA_FilterEnabled) {
        WSA_LOOKUP* pLookup = WSA_GetLookup(hLookup, FALSE);

        if (pLookup && pLookup->Filtered) {
            if (pLookup->DomainName)
                Dll_Free(pLookup->DomainName);

            if (pLookup->ServiceClassId)
                Dll_Free(pLookup->ServiceClassId);

            map_remove(&WSA_LookupMap, hLookup);

            Dll_Free(hLookup);

            if (WSA_DnsTraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS Filtered Request End (Hdl: %p)", hLookup);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            return NO_ERROR;
        }

        map_remove(&WSA_LookupMap, hLookup);
    }

    if (WSA_DnsTraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DNS Request End (Hdl: %p)", hLookup);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return __sys_WSALookupServiceEnd(hLookup);
}


//---------------------------------------------------------------------------
// DNS_CheckFilter
//---------------------------------------------------------------------------


_FX BOOLEAN DNS_CheckFilter(const WCHAR* pszName, WORD wType, LIST** ppEntries)
{
    if (!WSA_FilterEnabled || !pszName)
        return FALSE;

    ULONG path_len = wcslen(pszName);
    WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
    wmemcpy(path_lwr, pszName, path_len);
    path_lwr[path_len] = L'\0';
    _wcslwr(path_lwr);

    PATTERN* found;
    if (Pattern_MatchPathList(path_lwr, path_len, &WSA_FilterList, NULL, NULL, NULL, &found) > 0) {
        PVOID* aux = Pattern_Aux(found);
        // Pattern matched - return TRUE even if no IPs configured
        // When *aux is NULL, ppEntries will be NULL, causing NXDOMAIN to be returned
        *ppEntries = *aux ? (LIST*)*aux : NULL;
        Dll_Free(path_lwr);
        return TRUE;
    }

    Dll_Free(path_lwr);
    return FALSE;
}


//---------------------------------------------------------------------------
// DNSAPI_CreateDnsRecords
//---------------------------------------------------------------------------


_FX PDNS_RECORD DNSAPI_CreateDnsRecords(const WCHAR* pszName, WORD wType, LIST* pEntries)
{
    if (!pEntries || !pszName)
        return NULL;

    PDNS_RECORD pFirstRecord = NULL;
    PDNS_RECORD pLastRecord = NULL;

    // Filter entries by type
    IP_ENTRY* entry;
    for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        BOOLEAN match = FALSE;
        
        if (wType == DNS_TYPE_A && entry->Type == AF_INET)
            match = TRUE;
        else if (wType == DNS_TYPE_AAAA && entry->Type == AF_INET6)
            match = TRUE;

        if (!match)
            continue;

        // Allocate DNS record
        PDNS_RECORD pRecord = (PDNS_RECORD)Dll_Alloc(sizeof(DNS_RECORD));
        if (!pRecord)
            continue;

        memset(pRecord, 0, sizeof(DNS_RECORD));
        
        // Allocate and set name
        ULONG nameLen = (wcslen(pszName) + 1) * sizeof(WCHAR);
        pRecord->pName = (PWSTR)Dll_Alloc(nameLen);
        if (!pRecord->pName) {
            Dll_Free(pRecord);
            continue;
        }
        wcscpy(pRecord->pName, pszName);
        
        pRecord->wType = (entry->Type == AF_INET) ? DNS_TYPE_A : DNS_TYPE_AAAA;
        pRecord->wDataLength = (entry->Type == AF_INET) ? sizeof(IP4_ADDRESS) : sizeof(IP6_ADDRESS);
        pRecord->dwTtl = 3600; // 1 hour TTL

        // Set address data
        if (entry->Type == AF_INET) {
            pRecord->Data.A.IpAddress = entry->IP.Data32[3];
        }
        else if (entry->Type == AF_INET6) {
            memcpy(&pRecord->Data.AAAA.Ip6Address, entry->IP.Data, 16);
        }

        // Link records
        if (!pFirstRecord) {
            pFirstRecord = pRecord;
            pLastRecord = pRecord;
        }
        else {
            pLastRecord->pNext = pRecord;
            pLastRecord = pRecord;
        }
    }

    return pFirstRecord;
}


//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_W
//---------------------------------------------------------------------------


_FX DNS_STATUS DNSAPI_DnsQuery_W(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved)
{
    LIST* pEntries = NULL;
    
    if (DNS_CheckFilter(pszName, wType, &pEntries)) {
        PDNS_RECORD pRecords = DNSAPI_CreateDnsRecords(pszName, wType, pEntries);
        
        if (pRecords) {
            *ppQueryResults = pRecords;
            
            if (WSA_DnsTraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Query Intercepted: %s (Type: %d) - Using filtered response", pszName, wType);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
            
            return ERROR_SUCCESS;
        }
        
        // No matching records for this type
        if (WSA_DnsTraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS Query Intercepted: %s (Type: %d) - No matching records", pszName, wType);
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
        
        return DNS_ERROR_RCODE_NAME_ERROR;
    }

    // Not filtered, call original function
    DNS_STATUS status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    
    if (WSA_DnsTraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DNS Query: %s (Type: %d, Status: %d)", pszName, wType, status);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return status;
}


//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_A
//---------------------------------------------------------------------------


_FX DNS_STATUS DNSAPI_DnsQuery_A(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved)
{
    // Convert ANSI to Unicode
    if (!pszName)
        return __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    int nameLen = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
    WCHAR* wszName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, pszName, -1, wszName, nameLen);

    LIST* pEntries = NULL;
    
    if (DNS_CheckFilter(wszName, wType, &pEntries)) {
        PDNS_RECORD pRecords = DNSAPI_CreateDnsRecords(wszName, wType, pEntries);
        
        Dll_Free(wszName);
        
        if (pRecords) {
            *ppQueryResults = pRecords;
            
            if (WSA_DnsTraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Query Intercepted (ANSI): %S (Type: %d) - Using filtered response", pszName, wType);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
            
            return ERROR_SUCCESS;
        }
        
        if (WSA_DnsTraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS Query Intercepted (ANSI): %S (Type: %d) - No matching records", pszName, wType);
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
        
        return DNS_ERROR_RCODE_NAME_ERROR;
    }

    Dll_Free(wszName);

    // Not filtered, call original function
    DNS_STATUS status = __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    
    if (WSA_DnsTraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DNS Query (ANSI): %S (Type: %d, Status: %d)", pszName, wType, status);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return status;
}


//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_UTF8
//---------------------------------------------------------------------------


_FX DNS_STATUS DNSAPI_DnsQuery_UTF8(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved)
{
    // Convert UTF-8 to Unicode
    if (!pszName)
        return __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    int nameLen = MultiByteToWideChar(CP_UTF8, 0, pszName, -1, NULL, 0);
    WCHAR* wszName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, pszName, -1, wszName, nameLen);

    LIST* pEntries = NULL;
    
    if (DNS_CheckFilter(wszName, wType, &pEntries)) {
        PDNS_RECORD pRecords = DNSAPI_CreateDnsRecords(wszName, wType, pEntries);
        
        Dll_Free(wszName);
        
        if (pRecords) {
            *ppQueryResults = pRecords;
            
            if (WSA_DnsTraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Query Intercepted (UTF8): %S (Type: %d) - Using filtered response", pszName, wType);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
            
            return ERROR_SUCCESS;
        }
        
        if (WSA_DnsTraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS Query Intercepted (UTF8): %S (Type: %d) - No matching records", pszName, wType);
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
        
        return DNS_ERROR_RCODE_NAME_ERROR;
    }

    Dll_Free(wszName);

    // Not filtered, call original function
    DNS_STATUS status = __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    
    if (WSA_DnsTraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DNS Query (UTF8): %S (Type: %d, Status: %d)", pszName, wType, status);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return status;
}


//---------------------------------------------------------------------------
// DNSAPI_DnsQueryEx
//---------------------------------------------------------------------------


_FX DNS_STATUS DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle)
{
    if (!pQueryRequest || !pQueryResults)
        return __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);

    LIST* pEntries = NULL;
    const WCHAR* pszName = pQueryRequest->QueryName;
    WORD wType = pQueryRequest->QueryType;
    
    if (pszName && DNS_CheckFilter(pszName, wType, &pEntries)) {
        PDNS_RECORD pRecords = DNSAPI_CreateDnsRecords(pszName, wType, pEntries);
        
        if (pRecords) {
            memset(pQueryResults, 0, sizeof(DNS_QUERY_RESULT));
            pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
            pQueryResults->QueryStatus = ERROR_SUCCESS;
            pQueryResults->pQueryRecords = pRecords;
            
            if (WSA_DnsTraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS QueryEx Intercepted: %s (Type: %d) - Using filtered response", pszName, wType);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
            
            return ERROR_SUCCESS;
        }
        
        if (WSA_DnsTraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS QueryEx Intercepted: %s (Type: %d) - No matching records", pszName, wType);
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
        
        memset(pQueryResults, 0, sizeof(DNS_QUERY_RESULT));
        pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
        pQueryResults->QueryStatus = DNS_ERROR_RCODE_NAME_ERROR;
        return DNS_ERROR_RCODE_NAME_ERROR;
    }

    // Not filtered, call original function
    DNS_STATUS status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
    
    if (WSA_DnsTraceFlag && pszName) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DNS QueryEx: %s (Type: %d, Status: %d)", pszName, wType, status);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return status;
}


//---------------------------------------------------------------------------
// DNSAPI_CreateDnsMessageBuffer
//---------------------------------------------------------------------------


_FX PDNS_MESSAGE_BUFFER DNSAPI_CreateDnsMessageBuffer(const WCHAR* pszName, WORD wType, LIST* pEntries)
{
    if (!pEntries || !pszName)
        return NULL;

    // Convert domain name to DNS wire format (length-prefixed labels)
    char dnsName[256];
    int dnsNameLen = 0;
    
    // Convert Unicode to ANSI
    int nameLen = WideCharToMultiByte(CP_ACP, 0, pszName, -1, NULL, 0, NULL, NULL);
    if (nameLen <= 0 || nameLen > 253)
        return NULL;
    
    char asciiName[256];
    WideCharToMultiByte(CP_ACP, 0, pszName, -1, asciiName, sizeof(asciiName), NULL, NULL);
    
    // Convert to DNS wire format (e.g., "www.example.com" -> "\3www\7example\3com\0")
    char* src = asciiName;
    char* dst = dnsName;
    char* labelStart = dst + 1;
    *dst = 0;
    
    while (*src) {
        if (*src == '.') {
            *dst = (char)(labelStart - dst - 1);
            dst = labelStart;
            labelStart = dst + 1;
            *dst = 0;
        } else {
            *labelStart++ = *src;
        }
        src++;
    }
    if (labelStart > dst + 1) {
        *dst = (char)(labelStart - dst - 1);
        dst = labelStart;
    }
    *dst++ = 0;
    dnsNameLen = (int)(dst - dnsName);
    
    // Count matching IP entries
    DWORD ipCount = 0;
    IP_ENTRY* entry;
    for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((wType == DNS_TYPE_A && entry->Type == AF_INET) ||
            (wType == DNS_TYPE_AAAA && entry->Type == AF_INET6)) {
            ipCount++;
        }
    }
    
    if (ipCount == 0)
        return NULL;
    
    // Calculate buffer size
    // DNS packet: Header (12 bytes) + Question section + Answer section
    DWORD questionSize = dnsNameLen + 4; // name + type (2) + class (2)
    DWORD answerRecordSize = 0;
    
    for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((wType == DNS_TYPE_A && entry->Type == AF_INET) ||
            (wType == DNS_TYPE_AAAA && entry->Type == AF_INET6)) {
            // name (pointer: 2 bytes) + type (2) + class (2) + ttl (4) + rdlength (2) + rdata
            answerRecordSize += 2 + 2 + 2 + 4 + 2 + (entry->Type == AF_INET ? 4 : 16);
        }
    }
    
    // Allocate raw buffer for DNS packet (no DNS_MESSAGE_BUFFER header, just raw bytes)
    DWORD packetSize = 12 + questionSize + answerRecordSize;
    PDNS_MESSAGE_BUFFER pMsgBuf = (PDNS_MESSAGE_BUFFER)Dll_Alloc(packetSize);
    if (!pMsgBuf)
        return NULL;
    
    memset(pMsgBuf, 0, packetSize);
    
    // Build DNS header - start at beginning of buffer
    BYTE* pData = (BYTE*)pMsgBuf;
    BYTE* pBase = pData;
    
    // Transaction ID (16 bits) - use a simple value
    *pData++ = 0x00;
    *pData++ = 0x01;
    
    // Flags (16 bits): Standard query response, no error
    // QR=1 (response), Opcode=0 (query), AA=1 (authoritative), TC=0, RD=1, RA=1, Z=0, RCODE=0
    *pData++ = 0x85; // 10000101
    *pData++ = 0x80; // 10000000
    
    // QDCOUNT (16 bits) - 1 question
    *pData++ = 0x00;
    *pData++ = 0x01;
    
    // ANCOUNT (16 bits) - number of answers
    *pData++ = (BYTE)(ipCount >> 8);
    *pData++ = (BYTE)(ipCount & 0xFF);
    
    // NSCOUNT (16 bits) - 0 authority records
    *pData++ = 0x00;
    *pData++ = 0x00;
    
    // ARCOUNT (16 bits) - 0 additional records
    *pData++ = 0x00;
    *pData++ = 0x00;
    
    // Question section
    memcpy(pData, dnsName, dnsNameLen);
    pData += dnsNameLen;
    
    // QTYPE (16 bits)
    *pData++ = (BYTE)(wType >> 8);
    *pData++ = (BYTE)(wType & 0xFF);
    
    // QCLASS (16 bits) - IN (Internet)
    *pData++ = 0x00;
    *pData++ = 0x01;
    
    // Answer section
    for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((wType == DNS_TYPE_A && entry->Type == AF_INET) ||
            (wType == DNS_TYPE_AAAA && entry->Type == AF_INET6)) {
            
            // Name (pointer to question name)
            *pData++ = 0xC0; // Pointer flag
            *pData++ = 0x0C; // Offset to name in question (after header)
            
            // TYPE (16 bits)
            WORD type = (entry->Type == AF_INET) ? DNS_TYPE_A : DNS_TYPE_AAAA;
            *pData++ = (BYTE)(type >> 8);
            *pData++ = (BYTE)(type & 0xFF);
            
            // CLASS (16 bits) - IN
            *pData++ = 0x00;
            *pData++ = 0x01;
            
            // TTL (32 bits) - 3600 seconds
            *pData++ = 0x00;
            *pData++ = 0x00;
            *pData++ = 0x0E;
            *pData++ = 0x10;
            
            // RDLENGTH (16 bits)
            WORD rdLen = (entry->Type == AF_INET) ? 4 : 16;
            *pData++ = (BYTE)(rdLen >> 8);
            *pData++ = (BYTE)(rdLen & 0xFF);
            
            // RDATA
            if (entry->Type == AF_INET) {
                // IPv4 address (4 bytes)
                DWORD addr = entry->IP.Data32[3];
                *pData++ = (BYTE)(addr & 0xFF);
                *pData++ = (BYTE)((addr >> 8) & 0xFF);
                *pData++ = (BYTE)((addr >> 16) & 0xFF);
                *pData++ = (BYTE)((addr >> 24) & 0xFF);
            } else {
                // IPv6 address (16 bytes)
                memcpy(pData, entry->IP.Data, 16);
                pData += 16;
            }
        }
    }
    
    // DNS_MESSAGE_BUFFER is just the raw packet data, no need to set fields
    // The structure is properly formatted already
    
    return pMsgBuf;
}


//---------------------------------------------------------------------------
// DNSAPI_DnsQueryRaw
//---------------------------------------------------------------------------


_FX DNS_STATUS DNSAPI_DnsQueryRaw(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_MESSAGE_BUFFER* ppMsgBuf,
    PVOID*          pReserved)
{
    LIST* pEntries = NULL;
    
    if (DNS_CheckFilter(pszName, wType, &pEntries)) {
        // If filtered without IPs (blocking), return NXDOMAIN
        if (!pEntries) {
            if (WSA_DnsTraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS QueryRaw Intercepted: %s (Type: %d) - Blocked (NXDOMAIN)", pszName, wType);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
            return DNS_ERROR_RCODE_NAME_ERROR;
        }
        
        // Construct raw DNS response packet with configured IPs
        PDNS_MESSAGE_BUFFER pMsgBuf = DNSAPI_CreateDnsMessageBuffer(pszName, wType, pEntries);
        
        if (pMsgBuf) {
            *ppMsgBuf = pMsgBuf;
            
            if (WSA_DnsTraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS QueryRaw Intercepted: %s (Type: %d) - Using filtered response", pszName, wType);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
            
            return ERROR_SUCCESS;
        }
        
        // Failed to construct packet, fall through to original
        if (WSA_DnsTraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS QueryRaw: %s (Type: %d) - Failed to construct packet, passing through", pszName, wType);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    // Not filtered or packet construction failed - call original function
    DNS_STATUS status = __sys_DnsQueryRaw(pszName, wType, Options, pExtra, ppMsgBuf, pReserved);
    
    if (WSA_DnsTraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DNS QueryRaw: %s (Type: %d, Status: %d)", pszName, wType, status);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return status;
}
