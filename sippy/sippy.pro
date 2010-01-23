TEMPLATE = app
TARGET = sippy
DEPENDPATH += . \
	../libsparkle/headers
INCLUDEPATH += . \
	../libsparkle/headers
QT += network
debug:DEFINES += DEBUG

unix:POST_TARGETDEPS += ../libsparkle/libsparkle.a

# Input
HEADERS += DebugConsole.h \
	ConfigurationStorage.h \
	ConnectDialog.h \
	Singleton.h \
	Sippy.h \
	MessagingApplicationLayer.h
SOURCES += DebugConsole.cpp \
	main.cpp \
	ConfigurationStorage.cpp \
	ConnectDialog.cpp \
	Sippy.cpp \
	MessagingApplicationLayer.cpp
QMAKE_LIBS += -lsparkle
win32:QMAKE_LFLAGS += -L../libsparkle/release
else:QMAKE_LFLAGS += -L../libsparkle
FORMS += DebugConsole.ui \
	Roster.ui \
	ConnectDialog.ui
