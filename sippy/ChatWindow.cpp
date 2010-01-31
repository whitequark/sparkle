#include <QLabel>
#include "ChatWindow.h"
#include "MessagingApplicationLayer.h"
#include "Contact.h"
#include "ContactList.h"
#include "ContactWidget.h"
#include "ChatMessageEdit.h"
#include "Messaging.h"
#include <QTextBrowser>
#include <QVBoxLayout>
#include <Log.h>

using namespace Messaging;

ChatWindow::ChatWindow(MessagingApplicationLayer& _appLayer, SparkleAddress _peer) : appLayer(_appLayer), peer(_peer) {
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(6, 6, 6, 6);

	contact = appLayer.contactList().findByAddress(peer);
	if(contact != NULL) {
		ContactWidget* widget = new ContactWidget(appLayer, contact, true);

		layout->addWidget(widget);
	} else {
		QLabel* label = new QLabel(this);
		label->setMargin(7);
		label->setText(peer.pretty());

		layout->addWidget(label);
	}

	log = new QTextBrowser(this);
	layout->addWidget(log, 1);

	editor = new ChatMessageEdit(this);
	layout->addWidget(editor);

	setLayout(layout);

	setMinimumSize(250, 150);
	resize(500, 350);

	QString nick = peer.pretty();
	if(contact != NULL && contact->displayName() != "")
		nick = contact->displayName();
	setWindowTitle(tr("Chat with %1").arg(nick));

	connect(editor, SIGNAL(dispatchRequested()), SLOT(sendMessage()));
	connect(&appLayer, SIGNAL(messageAvailable(SparkleAddress)), SLOT(handleMessage()));

	handleMessage();
}

void ChatWindow::show() {
	QWidget::show();
	editor->setFocus();
}

void ChatWindow::sendMessage() {
	if(editor->toPlainText() == "")
		return;

	Message *message = new Message(editor->toPlainText(), QDateTime::currentDateTime(), peer);
	print(message->timestamp(), QString("<b>%1</b>: %2").arg(filterHTML(appLayer.nick()), filterHTML(message->text())).replace("\n", "<br>"));

	appLayer.sendControlPacket(message);

	editor->clear();
}

void ChatWindow::handleMessage() {
	Messaging::Message* message = appLayer.getControlPacket<Messaging::Message>();

	if(message != NULL) {
		QString nick = message->peer().pretty();
		if(contact != NULL && contact->displayName() != "")
			nick = contact->displayName();

		QString text;
		if(message->text().startsWith("/me ")) {
			text = QString("<b>* %1</b> %2").arg(filterHTML(nick), filterHTML(message->text()));
		} else {
			text = QString("<b>%1</b>: %2").arg(filterHTML(nick), filterHTML(message->text()));
		}

		print(message->timestamp(), text.replace("\n", "<br>"));
	}
}

void ChatWindow::print(QDateTime timestamp, QString str) {
	html += QString("<span style='color:gray;'>[%1]</span> %2<br>").arg(timestamp.toLocalTime().time().toString(), str);
	log->setHtml(html);
}
