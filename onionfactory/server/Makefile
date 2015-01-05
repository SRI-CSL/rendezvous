export OS_NAME

# Which OS is this? Can be overriden by setting it first
# eg to compile Windows edition on another platform use: $ make OS_NAME=Windows
ifeq ($(OS_NAME),)
override OS_NAME=$(shell uname -s)
endif

LIBFLAGS = -lcrypto -lcurl -lpbc -lgmp -L/usr/bin/lib 

ifeq ($(OS_NAME),Linux)
LIBFLAGS += -Wl,-Bsymbolic-functions
endif

ONIONFACTORY = ${HOME}/OnionFactory
ONIONFACTORYCGI = ${ONIONFACTORY}/thttpd/htdocs/index.html

SCRIPTS = ../bin/restart_onionfactory.sh 

MYSQL_CONFIG  = $(shell which mysql_config)

MYSQL_CFLAGS =  $(shell  ${MYSQL_CONFIG} --cflags)
MYSQL_LIBS  =  $(shell  ${MYSQL_CONFIG} --libs)

CFLAGS   += -Wall -pedantic -g -std=c99 -I../../client/src ${MYSQL_CFLAGS}

LIBS     =  ${LIBFLAGS} ${MYSQL_LIBS}

OBJS     = onion.o onionlib.o defiantclient.o defiantserver.o defiantcookie.o defiantbf.o nep.o serverlib.o serversql.o utils.o makeargv.o  crc.o 

all: ${OBJS} 
	${CC} ${CFLAGS} server_cgi_script.c  ${OBJS} ${LDFLAGS} ${LIBS} -o index.html
	${CC} ${CFLAGS} test_sql.c  ${OBJS} ${LIBS} ${LDFLAGS} ${LIBS} -o test_sql
	${CC} ${CFLAGS} test_onion_server.c  ${OBJS} ${LDFLAGS} ${LIBS} -o test_onion_server
	${CC} ${CFLAGS} generate_onion_file.c ${OBJS} ${LDFLAGS} ${LIBS} -o  generate_onion_file
	${CC} ${CFLAGS} check_onion_file.c  ${OBJS} ${LDFLAGS} ${LIBS} -o check_onion_file
	${CC} ${CFLAGS} onion_test.c  ${OBJS} ${LDFLAGS} ${LIBS} -o onion_test
	${CC} ${CFLAGS} key_test.c  ${OBJS} ${LDFLAGS} ${LIBS} -o key_test
	${CC} ${CFLAGS} collections_test.c  ${OBJS} ${LDFLAGS} ${LIBS} -o collections_test
	${CC} ${CFLAGS} captcha_test.c  ${OBJS} ${LDFLAGS} ${LIBS} -o captcha_test

serversql.o: serversql.c serversql.h
	${CC} ${CFLAGS}  $< -c 


%.o: %.c 
	${CC} ${CFLAGS} $< -c 

install: all dirs
	cp index.html ${ONIONFACTORYCGI}
	cp ${SCRIPTS} ${ONIONFACTORY}/bin
	echo OK

vtest:
	valgrind --leak-check=yes --leak-check=full  --dsymutil=yes ./index.html


clean:
	rm -rf *.o index.html test_sql test_onion_server  generate_onion_file check_onion_file onion_test collections_test *.dSYM



dirs:
	mkdir -p ${ONIONFACTORY}/bin
	mkdir -p ${ONIONFACTORY}/log
	mkdir -p ${ONIONFACTORY}/thttpd/htdocs
	mkdir -p ${ONIONFACTORY}/thttpd/run
	mkdir -p ${ONIONFACTORY}/thttpd/log


