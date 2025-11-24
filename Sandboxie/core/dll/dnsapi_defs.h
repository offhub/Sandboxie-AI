/*
 * Copyright 2024 David Xanatos, xanasoft.com
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
// DnsApi Definitions
//---------------------------------------------------------------------------

#ifndef _DNSAPI_DEFS_H
#define _DNSAPI_DEFS_H

#include <windns.h>


//---------------------------------------------------------------------------
// DnsQuery Function Pointers
//---------------------------------------------------------------------------


typedef DNS_STATUS (WINAPI *P_DnsQuery_W)(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQuery_A)(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQuery_UTF8)(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_RECORD*    ppQueryResults,
    PVOID*          pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQueryEx)(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle);

typedef DNS_STATUS (WINAPI *P_DnsQueryRaw)(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNS_MESSAGE_BUFFER* ppMsgBuf,
    PVOID*          pReserved);


#endif /* _DNSAPI_DEFS_H */
