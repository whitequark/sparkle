#ifndef PREFERENCESDIALOG_H
#define PREFERENCESDIALOG_H

#include "ui_PreferencesDialog.h"

class MessagingApplicationLayer;

class PreferencesDialog : public QDialog, private Ui::PreferencesDialog {
	Q_OBJECT
public:
	PreferencesDialog(MessagingApplicationLayer &appLayer, QWidget *parent);

public slots:
	void accept();

private:
	MessagingApplicationLayer &appLayer;
};

#endif // PREFERENCESDIALOG_H
