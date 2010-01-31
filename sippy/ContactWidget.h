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

#ifndef ROSTERITEM_H
#define ROSTERITEM_H

#include <QWidget>
#include "SparkleAddress.h"

class Contact;
class QLabel;
class QBoxLayout;
class QListWidgetItem;
class MessagingApplicationLayer;
class SparkleNode;

class ContactWidget : public QWidget {
	Q_OBJECT
public:
	ContactWidget(MessagingApplicationLayer &appLayer, Contact* contact, bool detailed = false);

	virtual QSize sizeHint() const;

protected:
	void contextMenuEvent(QContextMenuEvent *e);
	void mouseDoubleClickEvent(QMouseEvent *e);

signals:
	void menuRequested(QPoint point);
	void invoked();

private slots:
	void refresh();
	void processStateChange(SparkleAddress node);

private:
	Contact* contact;
	MessagingApplicationLayer &appLayer;
	bool detailed;

	QLabel *icon, *name, *info;
};

#endif // ROSTERITEM_H
