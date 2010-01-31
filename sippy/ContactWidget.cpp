/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
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

#include <QLabel>
#include <QVBoxLayout>
#include <QListWidgetItem>
#include <QContextMenuEvent>
#include <QImage>
#include "ContactWidget.h"
#include "Contact.h"
#include "Log.h"
#include "MessagingApplicationLayer.h"
#include "SparkleNode.h"
#include "pixmaps.h"

ContactWidget::ContactWidget(MessagingApplicationLayer &_appLayer, Contact* _contact, bool _detailed) : contact(_contact), appLayer(_appLayer), detailed(_detailed)
{
	if(!detailed) {
		icon = new QLabel();
		name = new QLabel();
		info = NULL;

		QBoxLayout* layout = new QHBoxLayout();
		layout->setContentsMargins(3, 0, 10, 0);
		layout->addWidget(icon, 0);
		layout->addWidget(name, 1);

		setLayout(layout);
	} else {
		icon = new QLabel();
		name = new QLabel();
		info = new QLabel();
		info->setIndent(5);

		QBoxLayout* innerLayout = new QVBoxLayout();
		innerLayout->setSpacing(0);
		innerLayout->setContentsMargins(0, 0, 0, 0);
		innerLayout->addWidget(name);
		innerLayout->addWidget(info);

		QBoxLayout* layout = new QHBoxLayout();
		layout->setContentsMargins(3, 0, 10, 0);
		layout->addWidget(icon, 0);
		layout->addLayout(innerLayout, 1);

		setLayout(layout);
	}

	connect(contact, SIGNAL(updated()), SLOT(refresh()));
	connect(&appLayer, SIGNAL(peerStateChanged(SparkleAddress)), SLOT(processStateChange(SparkleAddress)));

	setMinimumHeight(sizeHint().height());
	setMaximumHeight(sizeHint().height());

	refresh();
}

QSize ContactWidget::sizeHint() const {
	return QSize(0, layout()->minimumSize().height() + 2);
}

void ContactWidget::processStateChange(SparkleAddress address) {
	if(address == contact->address())
		refresh();
}

void ContactWidget::refresh() {
	QString nameText, infoText;
	QPixmap pixmap;

	if(contact->displayName().isEmpty())
		nameText = contact->textAddress();
	else
		nameText = contact->displayName();

	Messaging::PeerState state = appLayer.peerState(contact->address());
	switch(state) {
		case Messaging::Present:
		infoText = contact->statusText();
		break;

		case Messaging::NotPresent:
		infoText = tr("Offline");
		break;

		case Messaging::Unauthorized:
		infoText = QString("<i>%1</i>").arg(tr("Unauthorized"));
		break;

		case Messaging::Unavailable:
		infoText = QString("<i>%1</i>").arg(tr("Unavailable"));
		break;

		case Messaging::InternalError:
		infoText = QString("<i>%1</i>").arg(tr("Network error"));
		break;
	}

	if(!detailed) {
		if(state == Messaging::Present) {
			switch(contact->status()) {
				case Messaging::Online:
				pixmap = QPixmap(PIXMAP_SMALL_ONLINE);
				break;

				case Messaging::Away:
				pixmap = QPixmap(PIXMAP_SMALL_AWAY);
				break;

				case Messaging::Busy:
				pixmap = QPixmap(PIXMAP_SMALL_BUSY);
				break;
			}
		} else {
			pixmap = QPixmap(PIXMAP_SMALL_OFFLINE);
		}
	} else {
		if(state == Messaging::Present) {
			switch(contact->status()) {
				case Messaging::Online:
				pixmap = QPixmap(PIXMAP_LARGE_ONLINE);
				break;

				case Messaging::Away:
				pixmap = QPixmap(PIXMAP_LARGE_AWAY);
				break;

				case Messaging::Busy:
				pixmap = QPixmap(PIXMAP_LARGE_BUSY);
				break;
			}
		} else {
			pixmap = QPixmap(PIXMAP_LARGE_OFFLINE);
		}
	}

	name->setText(nameText);
	if(info) info->setText(infoText);
	icon->setPixmap(pixmap);
}

void ContactWidget::contextMenuEvent(QContextMenuEvent *e) {
	emit menuRequested(e->globalPos());
}
