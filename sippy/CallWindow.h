#ifndef CALLWINDOW_H
#define CALLWINDOW_H

#include "ui_CallWindow.h"
#include <SparkleAddress.h>

class MessagingApplicationLayer;
class Contact;

class CallWindow : public QWidget, private Ui_CallWindow {
	Q_OBJECT

	enum Status {
		Initializing,
		Standby,
		Calling,
		Talking,
	};

public:
	CallWindow(MessagingApplicationLayer& appLayer, Contact* contact);

public slots:
	virtual void close();

	void call();
	void hangup();
	void accept();

signals:
	void closed();

private slots:
	void handleCallOperate(SparkleAddress peer);

private:
	void updateStatus(Status newStatus, bool localRequest);

	MessagingApplicationLayer& appLayer;
	Contact* contact;
	Status status;
};

#endif // CALLWINDOW_H
