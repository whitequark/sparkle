#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <SparkleAddress.h>
#include <QWidget>
#include "MessagingApplicationLayer.h"

class ChatMessageEdit;
class QTextBrowser;

class ChatWindow : public QWidget {
	Q_OBJECT

public:
	ChatWindow(MessagingApplicationLayer& app, SparkleAddress peer);

public slots:
	virtual void show();
	void handleMessage();

private slots:
	void sendMessage();

private:
	void print(QDateTime timestamp, QString str);

	MessagingApplicationLayer &appLayer;
	SparkleAddress peer;
	Contact* contact;

	QTextBrowser* log;
	ChatMessageEdit* editor;

	QString html;
};

#endif // CHATWINDOW_H
