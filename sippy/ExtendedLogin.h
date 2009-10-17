#ifndef __EXTENDED_LOGIN__H__
#define __EXTENDED_LOGIN__H__

#include <QObject>

#include <QHostInfo>

class LinkLayer;

class ExtendedLogin: public QObject {
	Q_OBJECT

public:
	ExtendedLogin(LinkLayer *link, QObject *parent = 0);
	virtual ~ExtendedLogin();

public slots:
	void login(bool create, QString host, bool behindNat);

private slots:
	void sippyClosed();
	void linkShutDown();
	void linkJoinFailed();
	void linkJoined();

	void hostnameResolved(QHostInfo info);

signals:
	void loggedIn();
	void loginFailed(QString message);

private:
	void doRealLogin(QHostAddress address);

private:
	LinkLayer *link;

	bool isClosed, behindNat, createNetwork;
	QString enteredHost;
};

#endif

