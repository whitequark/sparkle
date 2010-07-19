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

#include <QMutex>
#include <QWaitCondition>
#include <QQueue>

#include <Mailbox>

class MailboxPrivate {
public:
	MailboxPrivate(int _size) : size(_size) {
		if(size == 0)
			size = 64;
	}

	QMutex mutex;
	QWaitCondition sendWait, recvWait;
	QQueue<void *> queue;
	int size;
};

Mailbox::Mailbox(MailboxPrivate &dd) : d_ptr(&dd) {
	
}

Mailbox::Mailbox(int size) : d_ptr(new MailboxPrivate(size)) {

}

Mailbox::~Mailbox() {
	delete d_ptr;
}

void Mailbox::send(void *item) {
	Q_D(Mailbox);

	d->mutex.lock();

	if(d->queue.count() == d->size) {
		d->sendWait.wait(&d->mutex);
	}

	bool wake = d->queue.empty();

	d->queue.enqueue(item);

	d->mutex.unlock();

	if(wake)
		d->recvWait.wakeOne();
}

bool Mailbox::trySend(void *item) {
	Q_D(Mailbox);

	d->mutex.lock();

	bool sent = d->queue.count() < d->size, wake = false;

	if(sent) {
		wake = d->queue.empty();

		d->queue.enqueue(item);
	}

	d->mutex.unlock();

	if(wake)
		d->recvWait.wakeOne();

	return sent;
}

bool Mailbox::receive(void **item, unsigned long time) {
	Q_D(Mailbox);

	d->mutex.lock();

	bool ret;

	if(d->queue.empty()) {
		ret = d->recvWait.wait(&d->mutex, time);

		if(ret) {
			if(item)
				*item = d->queue.dequeue();
			else
				d->queue.dequeue();
		}

	} else {
		*item = d->queue.dequeue();

		ret = true;
	}

	d->mutex.unlock();

	if(ret)
		d->sendWait.wakeOne();

	return ret;
}

bool Mailbox::tryReceive(void **item) {
	Q_D(Mailbox);

	d->mutex.lock();

	bool ret = !d->queue.empty();

	if(ret) {
		if(*item)
			*item = d->queue.dequeue();
		else
			d->queue.dequeue();
	}

	d->mutex.unlock();

	if(ret)
		d->sendWait.wakeOne();

	return ret;
}

