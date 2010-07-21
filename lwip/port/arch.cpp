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

#include <QSemaphore>
#include <QTime>

#include <lwip/sys.h>
#include <Mailbox>
#include <LwIPThread>

static struct sys_timeouts sys_timeouts;

void sys_init() {

}

sys_sem_t sys_sem_new(u8_t count) {
	return new QSemaphore(count);
}

void sys_sem_free(sys_sem_t sem) {
	delete static_cast<QSemaphore *>(sem);
}

void sys_sem_signal(sys_sem_t sem) {
	QSemaphore *semaphore = static_cast<QSemaphore *>(sem);

	semaphore->release();
}

u32_t sys_arch_sem_wait(sys_sem_t sem, u32_t timeout) {
	QSemaphore *semaphore = static_cast<QSemaphore *>(sem);

	QTime time;

	time.start();

	bool ret = semaphore->tryAcquire(timeout ? timeout : -1);

	return ret ? time.elapsed() : SYS_ARCH_TIMEOUT;
}

sys_mbox_t sys_mbox_new(int size) {
	return new Mailbox(size);
}

void sys_mbox_free(sys_mbox_t mbox) {
	delete static_cast<Mailbox *>(mbox);
}

void sys_mbox_post(sys_mbox_t mbox, void *msg) {
	static_cast<Mailbox *>(mbox)->send(msg);
}

err_t sys_mbox_trypost (sys_mbox_t mbox, void *msg) {
	if(static_cast<Mailbox *>(mbox)->trySend(msg)) {
		return ERR_OK;
	} else {
		return ERR_MEM;
	}
}

u32_t sys_arch_mbox_fetch(sys_mbox_t mbox, void **msg, u32_t timeout) {
	Mailbox *box = static_cast<Mailbox *>(mbox);

	QTime time;

	time.start();

	bool ret = box->receive(msg, timeout ? timeout : ULONG_MAX);

	return ret ? time.elapsed() : SYS_ARCH_TIMEOUT;
}

u32_t sys_arch_mbox_tryfetch(sys_mbox_t mbox, void **msg) {
	Mailbox *box = static_cast<Mailbox *>(mbox);

	bool ret = box->tryReceive(msg);

	return ret ? ERR_OK : 0;
}

struct sys_timeouts *sys_arch_timeouts(void) {
	LwIPThread *current = qobject_cast<LwIPThread *>(QThread::currentThread());

	if(current) {
		return current->timeouts();
	} else {	
		return &sys_timeouts;
	}
}

sys_thread_t sys_thread_new(char *name, void (* thread)(void *arg), void *arg, int stacksize, int prio) {
	Q_UNUSED(stacksize);
	Q_UNUSED(prio);

	return new LwIPThread(thread, arg);
}
	
