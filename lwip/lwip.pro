#
# lwIP Qt port
# Copyright (c) 2010 Sergey Gridassov
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

TARGET      = lwip
TEMPLATE    = lib
CONFIG += staticlib
INCLUDEPATH = port/headers src/include src/include/ipv4

QT -= gui

SOURCES    += port/Mailbox.cpp port/LwIPThread.cpp port/arch.cpp
HEADERS    += port/headers/Mailbox port/headers/LwIPThread
 
SOURCES += src/core/dhcp.c src/core/dns.c src/core/init.c src/core/mem.c \
	src/core/memp.c src/core/netif.c src/core/pbuf.c src/core/raw.c \
	src/core/stats.c src/core/sys.c src/core/tcp.c src/core/tcp_in.c \
	src/core/tcp_out.c src/core/udp.c

SOURCES += src/core/ipv4/autoip.c src/core/ipv4/icmp.c src/core/ipv4/igmp.c \
	src/core/ipv4/inet.c src/core/ipv4/inet_chksum.c src/core/ipv4/ip.c \
	src/core/ipv4/ip_addr.c src/core/ipv4/ip_frag.c

SOURCES += src/api/api_lib.c src/api/api_msg.c src/api/err.c src/api/netbuf.c \
	src/api/netdb.c src/api/netifapi.c src/api/sockets.c src/api/tcpip.c

SOURCES += src/netif/etharp.c
