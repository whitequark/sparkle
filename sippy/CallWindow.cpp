#include "CallWindow.h"
#include "MessagingApplicationLayer.h"
#include "ContactWidget.h"
#include "Contact.h"
#include <QBoxLayout>
#include "Log.h"

CallWindow::CallWindow(MessagingApplicationLayer& _appLayer, Contact* _contact) : appLayer(_appLayer), contact(_contact) {
	setupUi(this);

	ContactWidget* infoWidget = new ContactWidget(appLayer, contact, true);
	Ui_CallWindow::layout->insertWidget(0, infoWidget);

	setWindowTitle(tr("Talk with %1").arg(contact->fallbackName()));

	connect(hangupButton, SIGNAL(clicked()), SLOT(hangup()));

	status = Initializing;
	updateStatus(Standby, true);
}

void CallWindow::close() {
	deleteLater();
	QWidget::close();
}

void CallWindow::updateStatus(Status newStatus, bool localRequest) {
	if(status == newStatus)
		return;

	Log::debug("gui.cw: switching %1 to %2 state") << status << newStatus;

	if(status == Standby) {
		connect(&appLayer, SIGNAL(callOperateAvailable(SparkleAddress)), SLOT(handleCallOperate(SparkleAddress)));

		Q_ASSERT(localRequest == true);

		if(newStatus == Calling) {
			Messaging::CallRequest* req = new Messaging::CallRequest(contact->address());
			appLayer.sendControlPacket(req);
		} else if(newStatus == Talking) {
			Messaging::CallOperate* op = new Messaging::CallOperate(Messaging::AcceptCall, contact->address());
			appLayer.sendControlPacket(op);
		}
	} else if(status != Initializing) {
		Q_ASSERT(newStatus != Calling);

		if(newStatus == Talking) {
			if(status == Calling) {
				Q_ASSERT(localRequest == false);
			} else if(newStatus == Standby) {
				Q_ASSERT(localRequest == true);
			}
		} else if(newStatus == Standby) {
			disconnect(&appLayer, SIGNAL(callOperateAvailable(SparkleAddress)), this, SLOT(handleCallOperate(SparkleAddress)));

			if(localRequest) {
				Messaging::CallOperate* op = new Messaging::CallOperate(Messaging::HangupCall, contact->address());
				appLayer.sendControlPacket(op);
			}
		}
	}

	status = newStatus;
	switch(status) {
		case Standby:
		callStatus->setText(tr("standby"));
		break;

		case Calling:
		callStatus->setText(tr("calling..."));
		break;

		case Talking:
		callStatus->setText(tr("talking"));
		break;

		default:
		callStatus->setText(tr("internal error"));
	}
}

void CallWindow::call() {
	if(status == Standby) {
		updateStatus(Calling, true);
	} else {
		Log::error("gui.cw: call() called while not in Standby");
	}
}

void CallWindow::hangup() {
	if(status != Standby) {
		updateStatus(Standby, true);
	} else {
		close();
	}
}

void CallWindow::accept() {
	updateStatus(Talking, true);
}

void CallWindow::handleCallOperate(SparkleAddress peer) {
	if(contact->address() == peer) {
		Messaging::CallOperate* req = appLayer.getControlPacket<Messaging::CallOperate>();
		if(req->action() == Messaging::AcceptCall) {
			updateStatus(Talking, false);
		} else if(req->action() == Messaging::HangupCall || req->action() == Messaging::RejectCall) {
			updateStatus(Standby, false);
		}
	}
}
