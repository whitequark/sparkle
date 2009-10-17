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

#ifndef __SIPPY_WINDOW__H__
#define __SIPPY_WINDOW__H__

#include "ui_SippyWindow.h"

class ExtendedLogin;

class SippyWindow : public QMainWindow, private Ui_SippyWindow {
	Q_OBJECT

public:
	SippyWindow(QWidget *parent = 0);
	virtual ~SippyWindow();

	void setExtendedLogin(ExtendedLogin *ext);

private slots:
	void on_loginToNetwork_toggled(bool checked);
	void on_createNetwork_toggled(bool checked);
	void on_login_clicked();

	void onLoggedIn();
	void onLoginFailed(QString msg);

private:
	ExtendedLogin *extendedLogin;
};

#endif


