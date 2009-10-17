#include <QApplication>
#include <QFile>

#include <Log.h>
#include <Router.h>
#include <UdpPacketTransport.h>

#include "SippyApplicationLayer.h"
#include "ExtendedLogin.h"
#include "SippyWindow.h"
#include "DebugConsole.h"

int main(int argc, char *argv[]) {
	QApplication app(argc, argv);

	RSAKeyPair hostPair;
	
//	if(!QFile::exists(configDir + "/rsa_key")) {
		if(!hostPair.generate(256))
			Log::fatal("cannot generate new keypair");

//		if(!hostPair.writeToFile(configDir + "/rsa_key"))
//			Log::fatal("cannot write new keypair");
//	} else {
//		if(!hostPair.readFromFile(configDir + "/rsa_key"))
//			Log::fatal("cannot read RSA keypair");
//	}

	DebugConsole *cons = new DebugConsole();
	cons->show();

	SippyWindow *win = new SippyWindow();

	Router router;
	UdpPacketTransport transport(QHostAddress::Any, 1851);

	SippyApplicationLayer *sippyApp = new SippyApplicationLayer(router);

	LinkLayer linkLayer(router, transport, hostPair, sippyApp);

	ExtendedLogin *ext = new ExtendedLogin(&linkLayer);

	win->setExtendedLogin(ext);

	win->show();

	return app.exec();
}

