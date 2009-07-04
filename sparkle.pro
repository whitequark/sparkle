TEMPLATE = app
TARGET = sparkgap
DEPENDPATH += .
INCLUDEPATH += .
QMAKE_LIBS += -lssl
QT -= gui
QT += network

HEADERS += Log.h \
	RSAKeyPair.h \
	ArgumentParser.h \
	LinkLayer.h \
	SparkleNode.h \
	BlowfishKey.h \
	PacketTransport.h \
	UdpPacketTransport.h \
	SHA1Digest.h \
	RouteManager.h
SOURCES += main.cpp \
	Log.cpp \
	RSAKeyPair.cpp \
	ArgumentParser.cpp \
	LinkLayer.cpp \
	SparkleNode.cpp \
	BlowfishKey.cpp \
	UdpPacketTransport.cpp \
	SHA1Digest.cpp \
	RouteManager.cpp
unix { 
	SOURCES += LinuxTAP.cpp
	HEADERS += LinuxTAP.h
}
