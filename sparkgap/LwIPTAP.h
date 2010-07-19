/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2010 Sergey Gridassov
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

#ifndef __LWIP_TAP_H__
#define __LWIP_TAP_H__

#include <lwip/netif.h>

#include "TapInterface.h"

class LwIPTAP: public TapInterface {
	Q_OBJECT

public:
	LwIPTAP(QObject *parent = 0);
	virtual ~LwIPTAP();

public slots:
	virtual void setupInterface(Sparkle::SparkleAddress ha, QHostAddress ip);
	virtual void sendPacket(QByteArray packet);

signals:
	void havePacket(QByteArray packet);

private:
	static err_t if_init(struct netif *netif);
	static err_t if_output(struct netif *netif, struct pbuf *p);

	void receive(QByteArray data);

	bool m_registered;
	static struct netif interface;
	static QByteArray m_hw;
};

#endif


