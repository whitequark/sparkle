TEMPLATE = app
TARGET = sippy
DEPENDPATH += . \
	../libsparkle/headers
INCLUDEPATH += . \
	../libsparkle/headers
QT += network

debug {
	DEFINES += DEBUG
}

# Input
HEADERS += DebugConsole.h \
	ConfigurationStorage.h \
	SippyApplicationLayer.h \
	ConnectDialog.h \
	Singleton.h \
	Sippy.h
SOURCES += DebugConsole.cpp \
	main.cpp \
	ConfigurationStorage.cpp \
	SippyApplicationLayer.cpp \
	ConnectDialog.cpp \
	Sippy.cpp
QMAKE_LIBS += -lsparkle
win32:QMAKE_LFLAGS += -L../libsparkle/release
else:QMAKE_LFLAGS += -L../libsparkle
FORMS += DebugConsole.ui \
	Roster.ui \
	ConnectDialog.ui
