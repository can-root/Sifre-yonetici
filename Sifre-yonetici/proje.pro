QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = PasswordManager
TEMPLATE = app

SOURCES += main.cpp

LIBS += -lssl -lcrypto
