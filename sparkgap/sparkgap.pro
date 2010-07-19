TEMPLATE = app
TARGET = sparkgap
DEPENDPATH += . ../libsparkle/headers
INCLUDEPATH += . ../libsparkle/headers
unix:PRE_TARGETDEPS += ../libsparkle/libsparkle.a

INCLUDEPATH += ../lwip/port/headers ../lwip/src/include ../lwip/src/include/ipv4

QT -= gui
QT += network

HEADERS += ArgumentParser.h EthernetApplicationLayer.h TapInterface.h LwIPTAP.h

SOURCES += main.cpp ArgumentParser.cpp EthernetApplicationLayer.cpp LwIPTAP.cpp

LIBS += -lsparkle -llwip
win32:{
	contains(QMAKESPEC,msvc) {
		release:QMAKE_LFLAGS += -L../libsparkle/release -L../lwip/release
		debug:QMAKE_LFLAGS += -L../libsparkle/debug -L ../lwip/debug
	} else {
		release:QMAKE_LFLAGS += /LIBPATH:../libsparkle/release;../lwip/debug
		debug:QMAKE_LFLAGS += /LIBPATH:../libsparkle/debug;../lwip/debug
	}
} else:QMAKE_LFLAGS += -L../libsparkle -L../lwip

unix {
	SOURCES += LinuxTAP.cpp SignalHandler.cpp
	HEADERS += LinuxTAP.h SignalHandler.h
}

win32 {
	CONFIG -= windows
	CONFIG += console
}
