TEMPLATE = app
CONFIG += console c++11 link_pkgconfig
CONFIG -= app_bundle
QT += widgets network
isEmpty(VERSION):VERSION=1.0.6.0
PKGCONFIG += openssl libpcsclite
INCLUDEPATH += ../host-shared
LIBS += -ldl
DEFINES += VERSION=\\\"$$VERSION\\\"
SOURCES += \
    ../host-shared/Labels.cpp \
    ../host-shared/Logger.cpp \
    ../host-shared/BinaryUtils.cpp \
    ../host-shared/PKCS11Path.cpp \
    chrome-host.cpp
HEADERS += *.h ../host-shared/*.h
RESOURCES += chrome-token-signing.qrc
target.path = /usr/bin
hostconf.path = /etc/opt/chrome/native-messaging-hosts
hostconf.files += ee.nortal.sign_mass.json
# https://bugzilla.mozilla.org/show_bug.cgi?id=1318461
ffconf.path = /usr/lib/mozilla/native-messaging-hosts
ffconf.files += ff/ee.nortal.sign_mass.json
extension.path = /opt/google/chrome/extensions
extension.files += ../fhflklnpgjhdjcnlnlnoeomfebmbjkkk.json
ffextension.path = /usr/share/mozilla/extensions/{e0178cfd-2cfb-4f10-a53c-c71064f42bce}
ffextension.files += ../{443830f0-1fff-4f9a-aa1e-444bafbc7319}.xpi
INSTALLS += target hostconf ffconf extension ffextension
