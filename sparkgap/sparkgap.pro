TEMPLATE = app
TARGET = sparkgap
DEPENDPATH += . ../libsparkle/headers
INCLUDEPATH += . ../libsparkle/headers
unix:PRE_TARGETDEPS += ../libsparkle/libsparkle.a

CONFIG -= debug
CONFIG += release

QT -= gui
QT += network

HEADERS += ArgumentParser.h EthernetApplicationLayer.h TapInterface.h

SOURCES += main.cpp ArgumentParser.cpp EthernetApplicationLayer.cpp

QMAKE_LIBS += -lsparkle

win32 {
	QMAKE_LFLAGS += -L../libsparkle/release
} else {
	QMAKE_LFLAGS += -L../libsparkle
}

unix {
	SOURCES += LinuxTAP.cpp SignalHandler.cpp
	HEADERS += LinuxTAP.h SignalHandler.h
}

win32 {
	QMAKE_LIBS += -lws2_32

	CONFIG -= windows
	CONFIG += console
}
