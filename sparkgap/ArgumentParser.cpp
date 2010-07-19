/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#include <QCoreApplication>
#include <QtDebug>

#include <Sparkle/Log>

#include "ArgumentParser.h"

using namespace Sparkle;

static void helpCallback(void *u, QString) {
	ArgumentParser::help_callback_info_t *t = (ArgumentParser::help_callback_info_t *) u;

	printf("Usage: %s [OPTION]...\n", t->pclass->getArguments()[0].toAscii().data());
	printf("\nMandatory arguments to long options are mandatory for short options too.\n");

	foreach(ArgumentParser::option_t *option, *t->optionsList) {

		printf("  ");

		if(option->shortOpt != QChar::Null) {
			printf("-%c", option->shortOpt.toAscii());
		}

		if(!option->longOpt.isNull()) {
			if(option->shortOpt != QChar::Null)
				printf(", ");

			printf("--%s", option->longOpt.toAscii().data());
		}

		if(option->arg == ArgumentParser::OptionalArgument) {
			printf(" [%s]", option->argumentDescription.toAscii().data());
		} else if(option->arg == ArgumentParser::RequiredArgument) {
			printf(" %s", option->argumentDescription.toAscii().data());
		}

		printf("\t%s\n", option->optionDescription.toAscii().data());
	}
	
	t->callbackCalled = true;
}

ArgumentParser::ArgumentParser(QStringList arguments, QObject *parent) : QObject(parent) {
	this->arguments = arguments;

	hinfo.pclass = this;
	hinfo.optionsList = &this->optionsList;
	hinfo.callbackCalled = false;

	registerOption(QChar::Null, "help", NoArgument, NULL, &helpCallback, (void *) &hinfo, 
		"\tdisplay this help", QString());
}

ArgumentParser::~ArgumentParser() {
	foreach(option_t *ptr, optionsList)
		delete ptr;
}

bool ArgumentParser::parse() {
	bool invalid = false;

	for (QList<QString>::iterator i = arguments.begin() + 1; i != arguments.end(); i++) {
		QString &opt = *i;

		option_t *matching = 0;

		if(opt[0] == '-') {
			if(opt == "--")
				return true;

			if(opt[1] == '-') {
				foreach(option_t *option, optionsList)
					if(option->longOpt == opt.right(opt.count() - 2)) {
						matching = option;

						break;
					}

			} else if(opt.count() == 2) {
				foreach(option_t *option, optionsList)
					if(option->shortOpt == opt[1]) {
						matching = option;

						break;
					}

			} else {
				Log::warn("Invalid option %1") << opt;

				invalid = true;

				continue;
			}
		} else {
			Log::warn("Invalid option %1") << opt;

			invalid = true;

			continue;
		}

		if(matching) {
			QString arg;

			if(matching->arg == OptionalArgument || matching->arg == RequiredArgument) {
				if((i != arguments.end()-1) && (*(i + 1))[0] != '-') {
					i++;

					arg = *i;

				} else if(matching->arg == RequiredArgument) {
					Log::warn("Argument required for option %1") << opt;

					invalid = true;

					continue;
				} else {
					arg = "set";
				}
			} else {
				arg = "set";
			}

			if(!invalid) {
				if(matching->argument)
					*matching->argument = arg;

				if(matching->callback)
					matching->callback(matching->u, arg);
			}

		} else {
			Log::warn("Invalid option %1") << opt;

			invalid = true;

			continue;
		}

	}

	if(invalid)
		helpCallback((void *) &hinfo, QString());

	return !hinfo.callbackCalled;
}

void ArgumentParser::registerOption(QChar shortOpt, QString longOpt, ArgumentReq arg,
		QString *argument, void (*callback)(void *, QString), void *u,
		QString optionDescription, QString argumentDescription) {

	option_t *option = new option_t;
	option->shortOpt = shortOpt;
	option->longOpt = longOpt;
	option->argument = argument;
	option->callback = callback;
	option->u = u;
	option->arg = arg;
	option->optionDescription = optionDescription;
	option->argumentDescription = argumentDescription;

	optionsList.append(option);
}

QStringList ArgumentParser::getArguments() {
	return arguments;
}
