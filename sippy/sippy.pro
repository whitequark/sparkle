TEMPLATE = app
TARGET = sippy
DEPENDPATH += . \
    ../libsparkle/headers
INCLUDEPATH += . \
    ../libsparkle/headers
QT += network
debug:DEFINES += DEBUG
unix:PRE_TARGETDEPS += ../libsparkle/libsparkle.a
win32:LIBS += -ladvapi32

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
    Messaging.h
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
    Messaging.cpp
LIBS += -lsparkle
win32:{
	contains(QMAKESPEC,msvc) {
		release:QMAKE_LFLAGS += -L../libsparkle/release
		debug:QMAKE_LFLAGS += -L../libsparkle/debug
	} else {
		release:QMAKE_LFLAGS += /LIBPATH:../libsparkle/release
		debug:QMAKE_LFLAGS += /LIBPATH:../libsparkle/debug
	}
} else:QMAKE_LFLAGS += -L../libsparkle
FORMS += Roster.ui \
    ConnectDialog.ui \
    AddContactDialog.ui \
    EditContactDialog.ui \
    PreferencesDialog.ui
equals(QT_MAJOR_VERSION, "4"):lessThan(QT_MINOR_VERSION, "6") { 
    warning("Using bundled QtMultimedia from Qt 4.6.1")
    include("multimedia/audio.pri")
    INCLUDEPATH += multimedia/include \
        multimedia/include/QtMultimedia
    DEFINES += QT_BUILD_MULTIMEDIA_LIB
}
