/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
 *
 * Ths program is free software: you can redistribute it and/or modify
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
#include "RosterItem.h"
#include "Contact.h"
#include "Log.h"
#include "MessagingApplicationLayer.h"
#include "SparkleNode.h"

RosterItem::RosterItem(MessagingApplicationLayer &_appLayer, Contact* _contact, QListWidgetItem* listItem) : contact(_contact), _listItem(listItem), appLayer(_appLayer), selected(false)
{
	name = new QLabel(this);
	info = new QLabel(this);
	info->setIndent(10);
	info->hide();

	layout = new QVBoxLayout();
	layout->setSpacing(0);
	layout->setContentsMargins(QMargins(10, 0, 10, 0));
	layout->addWidget(name);
	layout->addWidget(info);

	setLayout(layout);

	connect(contact, SIGNAL(updated()), SLOT(update()));
	connect(&appLayer, SIGNAL(nodeStateChanged(SparkleNode*)), SLOT(processStateChange(SparkleNode*)));

	update();
}

void RosterItem::processStateChange(SparkleNode *node) {
	if(node->sparkleMAC() == contact->address())
		update();
}

void RosterItem::update() {
	QString nameText, infoText;

	if(contact->displayName().isEmpty())
		nameText = contact->textAddress();
	else
		nameText = contact->displayName();

	Messaging::NodeState state = appLayer.nodeState(contact->address());
	switch(state) {
		case Messaging::NotFound:
		infoText = QString("<i>%1</i>").arg(tr("Not found"));
		break;

		case Messaging::Unauthorized:
		infoText = QString("<i>%1</i>").arg(tr("Unauthorized"));
		break;

		case Messaging::Present:
		infoText = tr("Online");
		break;
	}

	QColor nameColor, infoColor;
	if(selected) {
		nameColor = infoColor = palette().highlightedText().color();
	} else {
		infoColor = palette().dark().color();
		if(state == Messaging::Present)
			nameColor = palette().foreground().color();
		else
			nameColor = infoColor;
	}

	name->setText(QString("<font color='%2'>%1</font>").arg(nameText).arg(nameColor.name()));
	info->setText(QString("<font color='%2'>%1</font>").arg(infoText).arg(infoColor.name()));

	_listItem->setSizeHint(QSize(0, layout->sizeHint().height() + 4));
}

void RosterItem::setSelected(bool _selected) {
	selected = _selected;
	update();
}

void RosterItem::setDetailed(bool _detailed) {
	info->setVisible(_detailed);
	update();
}

QListWidgetItem* RosterItem::listItem() const {
	return _listItem;
}

void RosterItem::contextMenuEvent(QContextMenuEvent *e) {
	emit menuRequested(e->globalPos());
}
