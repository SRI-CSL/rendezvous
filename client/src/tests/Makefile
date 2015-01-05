EXE =	tool test web trial random_test generate \
	make_request test_requests \
	nep_test test_bf test_crc test_64 test_cookie \
	outguess_test random_file test_blobs


DEFAULT_LIB_INSTALL_PATH = /usr/local/lib

CFLAGS += -I../ -L../

ifeq ($(OS_NAME),Darwin)
LDLIBS += ../defiantclient.dylib
else
ifeq ($(OS_NAME),Linux)
CFLAGS += -Wl,-rpath,$(LIBDEFIANTDIR),-rpath,./,-rpath,/usr/lib/,-rpath,/usr/local/lib/
LDLIBS += -ldefiantclient
DEPS += ../${SHAREDARCHIVE}
else
ifeq ($(OS_NAME),Windows)
LDFLAGS += ${OBJST}
DEPS +=
else
$(error "Unsupported OS: $(OS_NAME)")
endif # Windows
endif # Linux
endif # Darwin

# Remove '@' to get them to be verbose
COMPILE = @echo " * Compiling $@"; $(CC) -c $(CFLAGS)
LINK    = @echo " * Linking $@"; $(CC) $(CFLAGS) $(LDFLAGS)

all:  ${EXE}

${EXE}: %: %.c ${DEPS}
	$(LINK) -o $@ $@.c $(LDLIBS)

%.o: %.c $(DEPS)
	@echo "* Compiling $@";
	@$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	 sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

clean:
	@echo "==== Cleaning test..."
	$(RM) -rf ${EXE} *.dSYM

VALGRIND  = valgrind --leak-check=yes  --dsymutil=yes --trace-children=no

FULLGRIND = valgrind --leak-check=full --dsymutil=yes --show-reachable=yes

