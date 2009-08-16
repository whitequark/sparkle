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

#include <QMutex>
#include "random.h"
#include "crypto/havege.h"

static QMutex randomMutex;

int get_random(void *) {
	static havege_state *context = NULL;

	randomMutex.lock();

	if(context == NULL) { 
		context = new havege_state;

		havege_init(context);
	}

	int ret = havege_rand(context);

	randomMutex.unlock();

	return ret;
}

void random_bytes(unsigned char *buf, size_t length) {

	for(int *ptr = (int *) buf; length > 0; length -= sizeof(int), ptr++)
		*ptr = get_random(NULL);
}


