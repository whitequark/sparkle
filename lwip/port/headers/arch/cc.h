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

#ifndef __PORT__ARCH__CC__H__
#define __PORT__ARCH__CC__H__

#include <QtGlobal>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define LWIP_TIMEVAL_PRIVATE 0

typedef quint8 u8_t;
typedef quint16 u16_t;
typedef quint32 u32_t;

typedef qint8 s8_t;
typedef qint16 s16_t;
typedef qint32 s32_t;

#if QT_POINTER_SIZE == 4

typedef quint32 mem_ptr_t;

#elif QT_POINTER_SIZE == 8

typedef quint64 mem_ptr_t;

#else

#error Unknown pointer size

#endif

#define PACK_STRUCT_USE_INCLUDES 1
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_FIELD(a) a
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_END

#undef BYTE_ORDER

#if Q_BYTE_ORDER == Q_BIG_ENDIAN

#define BYTE_ORDER BIG_ENDIAN

#elif Q_BYTE_ORDER == Q_LITTLE_ENDIAN

#define BYTE_ORDER LITTLE_ENDIAN

#else

#error Unkonwn byte order

#endif

#define LWIP_PLATFORM_DIAG(a) printf a
#define LWIP_PLATFORM_ASSERT(x) { fputs(x, stderr); abort(); }

#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "z"
#endif

