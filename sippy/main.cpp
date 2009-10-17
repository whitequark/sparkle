#include <QApplication>
#include <QFile>

#include <Log.h>
#include <Router.h>
#include <UdpPacketTransport.h>

#include "SippyApplicationLayer.h"
#include "ExtendedLogin.h"
#include "SippyWindow.h"
#include "DebugConsole.h"
#include "ConfigurationStorage.h"

#ifdef Q_OS_UNIX
#include "SignalHandler.h"
#endif

int main(int argc, char *argv[]) {
	QApplication app(argc, argv);

	RSAKeyPair hostPair;
	
	QString keyName = ConfigurationStorage::instance()->getKeyName();

	if(!QFile::exists(keyName)) {
		if(!hostPair.generate(1024))
			Log::fatal("cannot generate new keypair");

		if(!hostPair.writeToFile(keyName))
			Log::fatal("cannot write new keypair");
	} else {
		if(!hostPair.readFromFile(keyName))
			Log::fatal("cannot read RSA keypair");
	}

	DebugConsole *cons = new DebugConsole();
	cons->show();

	SippyWindow *win = new SippyWindow();

	Router router;
	UdpPacketTransport transport(QHostAddress::Any, 1851);

	SippyApplicationLayer *sippyApp = new SippyApplicationLayer(router);

	LinkLayer linkLayer(router, transport, hostPair, sippyApp);

	ExtendedLogin *ext = new ExtendedLogin(&linkLayer);

#ifdef Q_OS_UNIX
	SignalHandler *sighandler = SignalHandler::getInstance();
	QObject::connect(sighandler, SIGNAL(sigint()), ext, SLOT(signaled()));
	QObject::connect(sighandler, SIGNAL(sigterm()), ext, SLOT(signaled()));
	QObject::connect(sighandler, SIGNAL(sighup()), ext, SLOT(signaled()));
#endif

	win->setExtendedLogin(ext);

	win->show();

	return app.exec();
}

