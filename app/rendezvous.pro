QT += network

#CONFIG += debug
CONFIG += release
CONFIG += staticlib

# We want a console window as a debugging help
CONFIG += console

INCLUDEPATH +=  ../client/src/

OBJECTS_DIR = build
MOC_DIR = build

# for building a release version with no stderr output
# DEFINES += QT_NO_WARNING_OUTPUT QT_NO_DEBUG_OUTPUT

DEFINES += 

win32 {
   INCLUDEPATH += ${HOME}/.cross/mingw/include/
   QMAKE_CFLAGS = -D__USE_MINGW_ANSI_STDIO=1 -D_GNU_SOURCE -DCURL_STATICLIB -L${HOME}/.cross/mingw/lib
   QMAKE_CXXFLAGS = -D__USE_MINGW_ANSI_STDIO=1 -D_GNU_SOURCE -DCURL_STATICLIB -L${HOME}/.cross/mingw/lib
   QMAKE_LFLAGS = -DCURL_STATICLIB -L${HOME}/.cross/mingw/lib
}

macx {
   CONFIG += app_bundle
   QMAKE_INFO_PLIST = arch/macx/Info.plist
 }

linux-g++ {

}

linux-g++-64 {

}

LIBS += -lcrypto  -lcurl -lpbc -lgmp 

HEADERS = src/rendezvous.h                   \
          src/onionmanager.h                 \
          src/onionrequest.h                 \
          src/curlthread.h                   \
          src/powthread.h                    \
          src/powreporter.h                  \
          src/stegoargs.h                    \
          src/stegospawner.h                 \
          src/dancer.h                       \
          src/util.h                         \
          ../client/src/defiantclient.h      \
          ../client/src/defiantrequest.h     \
          ../client/src/onion.h

SOURCES = src/main.cpp src/rendezvous.cpp    \
          src/onionmanager.cpp               \
          src/onionrequest.cpp               \
          src/curlthread.cpp                 \
          src/powthread.cpp                  \
          src/powreporter.cpp                \
          src/dancer.cpp                     \
          src/stegospawner.cpp               \
          src/stegoargs.cpp                  \
          src/util.cpp                       \
          ../client/src/defiantbf.c          \
          ../client/src/defiantclient.c      \
          ../client/src/defiantrequest.c     \
          ../client/src/defiantrequest_curl.c\
          ../client/src/onion.c              \
          ../client/src/outguess.c           \
          ../client/src/utils.c              \
          ../client/src/crc.c

win32 {
HEADERS +=					\
          ../client/src/platform.h

SOURCES +=					\
          ../client/src/platform.c
}

TARGET = rendezvous
