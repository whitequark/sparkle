#include "PreferencesDialog.h"
#include "MessagingApplicationLayer.h"

PreferencesDialog::PreferencesDialog(MessagingApplicationLayer &_appLayer, QWidget *parent) : QDialog(parent), appLayer(_appLayer) {
	setupUi(this);

	connect(this, SIGNAL(accepted()), SLOT(close()));

	nickEdit->connect(&appLayer, SIGNAL(nickChanged(QString)), SLOT(setText(QString)));
}

void PreferencesDialog::accept() {
	appLayer.setNick(nickEdit->text());
	emit accepted();
}
