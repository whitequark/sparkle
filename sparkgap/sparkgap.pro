TEMPLATE = app
TARGET = sparkgap
DEPENDPATH += . ../libsparkle/headers
INCLUDEPATH += . ../libsparkle/headers
unix:PRE_TARGETDEPS += ../libsparkle/libsparkle.a

QT -= gui
QT += network

HEADERS += ArgumentParser.h EthernetApplicationLayer.h TapInterface.h

SOURCES += main.cpp ArgumentParser.cpp EthernetApplicationLayer.cpp

LIBS += -lsparkle
win32:{
	contains(QMAKESPEC,msvc) {
		release:QMAKE_LFLAGS += -L../libsparkle/release
		debug:QMAKE_LFLAGS += -L../libsparkle/debug
	} else {
		release:QMAKE_LFLAGS += /LIBPATH:../libsparkle/release
		debug:QMAKE_LFLAGS += /LIBPATH:../libsparkle/debug
	}
	LIBS += -ladvapi32
} else:QMAKE_LFLAGS += -L../libsparkle

unix {
	SOURCES += LinuxTAP.cpp SignalHandler.cpp
	HEADERS += LinuxTAP.h SignalHandler.h
}

win32 {
	CONFIG -= windows
	CONFIG += console
}
