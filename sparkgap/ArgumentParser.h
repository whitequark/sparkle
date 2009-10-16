/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov
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

#ifndef __ARGUMENT_PARSER__H__
#define __ARGUMENT_PARSER__H__

#include <QObject>
#include <QStringList>

class ArgumentParser: public QObject {
	Q_OBJECT

public:
	ArgumentParser(QStringList arguments, QObject *parent = 0);
	virtual ~ArgumentParser();

	enum ArgumentReq {
		NoArgument,
		OptionalArgument,
		RequiredArgument
	};

	bool parse();
	void registerOption(QChar shortOpt, QString longOpt, ArgumentReq arg,
		QString *argument, void (*callback)(void *, QString), void *u,
		QString optionDescription, QString argumentDescription);

	QStringList getArguments();

	struct option_t {
		QChar		shortOpt;
		QString		longOpt;
		ArgumentReq	arg;
		QString *	argument;
		void		(*callback)(void *, QString);
		void *		u;

		QString		optionDescription;
		QString		argumentDescription;
	};

	struct help_callback_info_t {
		ArgumentParser		*pclass;
		QList<option_t *>	*optionsList;
		bool				callbackCalled;
	};

private:

	QStringList arguments;
	QList<option_t *> optionsList;

	help_callback_info_t hinfo;
};

#endif
