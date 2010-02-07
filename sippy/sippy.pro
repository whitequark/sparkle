TEMPLATE = app
TARGET = sippy
DEPENDPATH += . \
	../libsparkle/headers
INCLUDEPATH += . \
	../libsparkle/headers ../qtspeex/include
QT += network
debug:DEFINES += DEBUG
unix:PRE_TARGETDEPS += ../libsparkle/libsparkle.a

# Input
HEADERS += ConfigurationStorage.h \
	ConnectDialog.h \
	Singleton.h \
	MessagingApplicationLayer.h \
	ContactWidget.h \
	Roster.h \
	AddContactDialog.h \
	Contact.h \
	ContactList.h \
	EditContactDialog.h \
	StatusBox.h \
	pixmaps.h \
	PreferencesDialog.h \
	ChatWindow.h \
	ChatMessageEdit.h \
	Messaging.h \
	CallWindow.h
SOURCES += main.cpp \
	ConfigurationStorage.cpp \
	ConnectDialog.cpp \
	MessagingApplicationLayer.cpp \
	ContactWidget.cpp \
	Roster.cpp \
	AddContactDialog.cpp \
	Contact.cpp \
	ContactList.cpp \
	EditContactDialog.cpp \
	StatusBox.cpp \
	PreferencesDialog.cpp \
	ChatWindow.cpp \
	ChatMessageEdit.cpp \
	Messaging.cpp \
	CallWindow.cpp
QMAKE_LIBS += -lsparkle -lQtSpeex
win32: {
	release:QMAKE_LFLAGS += -L../libsparkle/release
	debug:QMAKE_LFLAGS += -L../libsparkle/debug
}
else: {
	QMAKE_LIBS += -lspeex -lspeexdsp
	QMAKE_LFLAGS += -L../libsparkle -L../qtspeex
}
FORMS += Roster.ui \
	ConnectDialog.ui \
	AddContactDialog.ui \
	EditContactDialog.ui \
	PreferencesDialog.ui \
	CallWindow.ui
equals(QT_MAJOR_VERSION, "4"):lessThan(QT_MINOR_VERSION, "6") {
	warning("Using bundled QtMultimedia from Qt 4.6.1")
	include("multimedia/audio.pri")
	INCLUDEPATH += multimedia/include \
		multimedia/include/QtMultimedia
	DEFINES += QT_BUILD_MULTIMEDIA_LIB
} else:QT += multimedia
