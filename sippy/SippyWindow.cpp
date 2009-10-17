/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Sergey Gridassov
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

#include <QTimer>

#include "ConfigurationStorage.h"

#include "ExtendedLogin.h"
#include "SippyWindow.h"

SippyWindow::SippyWindow(QWidget *parent) : QMainWindow(parent) {
	setupUi(this);

	ConfigurationStorage *cfg = ConfigurationStorage::instance();

	createNetwork->setChecked(cfg->createNetwork());
	option->setText(cfg->host());
	behindNat->setChecked(cfg->behindNat());
	autoLogin->setChecked(cfg->autoLogin());

	if(autoLogin->isChecked())
		QTimer::singleShot(0, this, SLOT(on_login_clicked()));
}

SippyWindow::~SippyWindow() {

}

void SippyWindow::on_loginToNetwork_toggled(bool checked) {
	if(checked) {
		optionLabel->setText(tr("Node or node list address:"));
	}
}

void SippyWindow::on_createNetwork_toggled(bool checked) {
	if(checked) {
		optionLabel->setText(tr("Local address:"));
	}
}

void SippyWindow::on_login_clicked() {
	stackedWidget->setCurrentWidget(loginSplashPage);

	ConfigurationStorage *cfg = ConfigurationStorage::instance();

	cfg->setCreateNetwork(createNetwork->isChecked());
	cfg->setHost(option->text());
	cfg->setBehindNat(behindNat->isChecked());
	cfg->setAutoLogin(autoLogin->isChecked());

	extendedLogin->login(createNetwork->isChecked(), option->text(), behindNat->isChecked());

}

void SippyWindow::setExtendedLogin(ExtendedLogin *ext) {
	extendedLogin = ext;

	connect(ext, SIGNAL(loggedIn()), SLOT(onLoggedIn()));
	connect(ext, SIGNAL(loginFailed(QString)), SLOT(onLoginFailed(QString)));
}

void SippyWindow::onLoginFailed(QString msg) {
	stackedWidget->setCurrentWidget(loginPage);

	loginFailure->setText(msg);
}

void SippyWindow::onLoggedIn() {
	stackedWidget->setCurrentWidget(rosterPage);
}

