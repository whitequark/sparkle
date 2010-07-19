/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Sparkle/Log>

using namespace Sparkle;

#include "random.h"

int get_random(void *) {
	int num;

	random_bytes(&num, sizeof(int));

	return num;
}

#if defined(Q_OS_UNIX)

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void random_bytes(void *buf, size_t length) {
	int random = open("/dev/urandom", O_RDONLY);

	if(random == -1)
		Log::fatal("open(/dev/urandom): %1") << strerror(errno);

	read(random, buf, length);

	close(random);
}

#elif defined(Q_OS_WIN32)

#define SystemFunction036 NTAPI SystemFunction036

#include <ntsecapi.h>

#undef SystemFunction036

void random_bytes(void *buf, size_t length) {
	RtlGenRandom(buf, length);
}

#else

#error random_bytes is not implemented for current platform

#endif

