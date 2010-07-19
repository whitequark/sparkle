/*
 * lwIP Qt port
 * Copyright (c) 2010 Sergey Gridassov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __PORT_LWIP_OPT__H__
#define __PORT_LWIP_OPT__H__

#define MEM_LIBC_MALLOC	1
#define IP_FRAG_USES_STATIC_BUF	0
#define LWIP_RAW		0
#define LWIP_NETIF_LOOPBACK	1
#define LWIP_POSIX_SOCKETS_IO_NAMES 0
#define LWIP_STATS	0

#undef LWIP_DEBUG

#define ETHARP_DEBUG                    LWIP_DBG_ON

#define NETIF_DEBUG                     LWIP_DBG_ON

#define PBUF_DEBUG                      LWIP_DBG_ON

#define API_LIB_DEBUG                   LWIP_DBG_ON

#define API_MSG_DEBUG                   LWIP_DBG_ON

#define SOCKETS_DEBUG                   LWIP_DBG_ON

#define ICMP_DEBUG                      LWIP_DBG_ON

#define IGMP_DEBUG                      LWIP_DBG_ON

#define INET_DEBUG                      LWIP_DBG_ON

#define IP_DEBUG                        LWIP_DBG_ON

#define IP_REASS_DEBUG                  LWIP_DBG_ON

#define RAW_DEBUG                       LWIP_DBG_ON

#define MEM_DEBUG                       LWIP_DBG_ON

#define MEMP_DEBUG                      LWIP_DBG_ON

#define SYS_DEBUG                       LWIP_DBG_ON

#define TCP_DEBUG                       LWIP_DBG_ON

#define TCP_INPUT_DEBUG                 LWIP_DBG_ON

#define TCP_FR_DEBUG                    LWIP_DBG_ON

#define TCP_RTO_DEBUG                   LWIP_DBG_ON

#define TCP_CWND_DEBUG                  LWIP_DBG_ON

#define TCP_WND_DEBUG                   LWIP_DBG_ON

#define TCP_OUTPUT_DEBUG                LWIP_DBG_ON

#define TCP_RST_DEBUG                   LWIP_DBG_ON

#define TCP_QLEN_DEBUG                  LWIP_DBG_ON

#define UDP_DEBUG                       LWIP_DBG_ON

#define TCPIP_DEBUG                     LWIP_DBG_ON

#define PPP_DEBUG                       LWIP_DBG_ON

#define SLIP_DEBUG                      LWIP_DBG_ON

#define DHCP_DEBUG                      LWIP_DBG_ON

#define AUTOIP_DEBUG                    LWIP_DBG_ON

#define SNMP_MSG_DEBUG                  LWIP_DBG_ON

#define SNMP_MIB_DEBUG                  LWIP_DBG_ON

#define DNS_DEBUG                       LWIP_DBG_ON

#endif

