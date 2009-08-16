TEMPLATE = app
TARGET = sparkgap
DEPENDPATH += .
INCLUDEPATH += .
CONFIG += release
CONFIG -= debug
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
	Router.h
SOURCES += main.cpp \
	Log.cpp \
	RSAKeyPair.cpp \
	ArgumentParser.cpp \
	LinkLayer.cpp \
	SparkleNode.cpp \
	BlowfishKey.cpp \
	UdpPacketTransport.cpp \
	SHA1Digest.cpp \
	Router.cpp \
	crypto/sha1.c crypto/rsa.c crypto/bignum.c crypto/havege.c crypto/timing.c \
	crypto/blowfish.c random.cpp

unix { 
	SOURCES += LinuxTAP.cpp
	HEADERS += LinuxTAP.h
}
