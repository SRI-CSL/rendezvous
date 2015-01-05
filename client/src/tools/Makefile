EXE =  fetcher validate_onion generate_request\
       defiantmasterkey_generator defiantparams_generator defiantpkg_generator\
       defiantmasterkey_info defiantparams_info defiantparams_check defiantpkg_info  defiantpkg_sql

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
else
$(error "Unsupported OS: $(OS_NAME)")
endif # Windows
endif # Linux
endif # Darwin

# Remove '@' to get them to be verbose
COMPILE	= @echo " * Compiling $@"; $(CC) -c $(CFLAGS)
LINK	= @echo " * Linking $@"; $(CC) $(CFLAGS) $(LDFLAGS)

all:  ${EXE}

${EXE}: %: %.c $(DEPS)
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
	@echo "==== Cleaning tools..."
	$(RM) -rf ${EXE} *.dSYM 

