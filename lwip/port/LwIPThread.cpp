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

#include <LwIPThread>

#include <lwip/sys.h>
#include <string.h>

class LwIPThreadPrivate {
public:
	LwIPThreadPrivate(void (*_thread)(void *arg), void *_arg) : thread(_thread), arg(_arg) {
		memset(&timeouts, 0, sizeof(struct sys_timeouts));
	}

	void (* thread)(void *arg);
	void *arg;
	struct sys_timeouts timeouts;
};

LwIPThread::LwIPThread(LwIPThreadPrivate &dd, QObject *parent) : QThread(parent), d_ptr(&dd) {
	connect(this, SIGNAL(finished()), SLOT(deleteLater()));

	start();
}

LwIPThread::LwIPThread(void (* thread)(void *arg), void *arg, QObject *parent) : QThread(parent), d_ptr(new LwIPThreadPrivate(thread, arg)) {
	connect(this, SIGNAL(finished()), SLOT(deleteLater()));

	start();
}

LwIPThread::~LwIPThread() {
	delete d_ptr;
}

struct sys_timeouts *LwIPThread::timeouts() {
	Q_D(LwIPThread);

	return &d->timeouts;
}

void LwIPThread::run() {
	Q_D(LwIPThread);

	d->thread(d->arg);
}

