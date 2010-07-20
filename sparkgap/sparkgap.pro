TEMPLATE = app
TARGET = sparkgap
DESTDIR = ../output

DEPENDPATH += . ../libsparkle/headers
INCLUDEPATH += ../libsparkle/headers \
	../lwip/port/headers ../lwip/src/include ../lwip/src/include/ipv4

QT -= gui
QT += network
CONFIG += console
	
LIBS += -L../output -lsparkle -llwip

HEADERS += ArgumentParser.h EthernetApplicationLayer.h TapInterface.h LwIPTAP.h

SOURCES += main.cpp ArgumentParser.cpp EthernetApplicationLayer.cpp LwIPTAP.cpp

unix {
	SOURCES += LinuxTAP.cpp SignalHandler.cpp
	HEADERS += LinuxTAP.h SignalHandler.h
}
