export OS_NAME

PWD = $(shell pwd)

# Which OS is this? Can be overriden by setting it first
# eg to compile Windows edition on another platform use: $ make OS_NAME=Windows
ifeq ($(OS_NAME),)
override OS_NAME=$(shell uname -s)
endif

HOST = $(shell hostname | cut -d '.' -f1)

HOST_CONFIG_FILE = ${HOST}_config
HOST_PRIVATE_KEY_FILE = ${HOST}_private_key.bin
DEFIANCE_PUBLIC_KEY_FILE = defiant_public.pem

ifeq ($(OS_NAME),Darwin)
APXS = apxs -D_MAC_
else 
APXS = apxs2
endif

HEADERS = freedom.h cryptlib.h freedom_config.h freedom_utils.h onionlib.h

LINK = -lcrypto  -lcurl -lpbc -lgmp  -Wl,-Bsymbolic-functions

FLAGS = -c -Wall -I../client/src

SRCS =	freedom_config.c \
	cryptlib.c \
	onionlib.c \
	defiantclient.c \
	defiantrequest.c \
	defiantrequest_curl.c \
	defiantbf.c \
	defiantcookie.c \
	freedom_protocol.c \
	freedom_utils.c \
	utils.c \
	crc.c \
	makeargv.c \
	jpeg_steg.c \
	defianterrors.c \
	../client/src/onion.c

LIBS = ${SRCS:.c=.lo}

OBJS = ${SRCS:.c=.o}

LIBTOOLS = ${SRCS:.c=.la}

MYSTERIES = ${SRCS:.c=.slo}

all: mod_freedom


.SUFFIXES:

.SUFFIXES: .lo .c

.c.lo:
	${APXS} ${FLAGS}  $<


mod_freedom: ${SRCS}
	${APXS} ${LINK} ${FLAGS} mod_freedom.c ${SRCS}

install:
	sudo ${APXS} -i mod_freedom.la


modconfig: all install
	sudo cp /var/www/index.html /var/www/error.html	
	sudo cp ${HOST_CONFIG_FILE} /etc/apache2/sites-available/default
# make the config area
	sudo mkdir -p /etc/apache2/mod_freedom_data/images
# copy over the images
	sudo cp images/*.jpg /etc/apache2/mod_freedom_data/images/
	sudo chown -R root:www-data /etc/apache2/mod_freedom_data/
	sudo chmod -R g+rw /etc/apache2/mod_freedom_data/
# copy over the private key
	sudo cp ${HOST_PRIVATE_KEY_FILE} /etc/apache2/mod_freedom_data/${HOST_PRIVATE_KEY_FILE}
	sudo chown root:www-data /etc/apache2/mod_freedom_data/${HOST_PRIVATE_KEY_FILE}
	sudo chmod g+rw /etc/apache2/mod_freedom_data/${HOST_PRIVATE_KEY_FILE} 
#copy over the DEFIANCE public key
	sudo cp ${DEFIANCE_PUBLIC_KEY_FILE} /etc/apache2/mod_freedom_data/${DEFIANCE_PUBLIC_KEY_FILE}
	sudo chown root:www-data /etc/apache2/mod_freedom_data/${DEFIANCE_PUBLIC_KEY_FILE}
	sudo chmod g+rw /etc/apache2/mod_freedom_data/${DEFIANCE_PUBLIC_KEY_FILE} 

deter: modconfig apache

apache:
	sudo service apache2 restart

onions:
# move over the fake onions
	sudo cp onions.bin /etc/apache2/mod_freedom_data/onions.bin
	sudo chown root:www-data /etc/apache2/mod_freedom_data/onions.bin
	sudo chmod g+rw /etc/apache2/mod_freedom_data/onions.bin 

ubuntu: modconfig onions apache


vstop:
	sudo /usr/sbin/apache2ctl stop


vstart:
	sudo rm -f /tmp/freedom_debug.log
	sudo touch /tmp/freedom_debug.log
	sudo chmod a+rw /tmp/freedom_debug.log
	sudo valgrind -v --log-file=/tmp/freedom_debug.log  --gen-suppressions=all --suppressions=${PWD}/valgrind.conf --trace-children=yes --leak-check=full /usr/sbin/apache2ctl start

#--gen-suppressions=all

clean:
	rm -f ${OBJS} ${MYSTERIES} ${LIBS} ${LIBTOOLS} *~ mod_freedom.o mod_freedom.lo mod_freedom.la mod_freedom.slo
	rm -rf .libs


