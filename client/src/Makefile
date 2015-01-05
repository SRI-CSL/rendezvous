ifeq ($(CC),)
CC = $(shell which cc)
endif

ifeq ($(AR),)
AR = $(shell which ar)
endif

# Which OS is this? Can be overriden by setting it first
# eg to compile Windows edition on another platform use: $ make OS_NAME=Windows
ifeq ($(OS_NAME),)
override OS_NAME=$(shell uname -s)
endif

ifeq ($(OS_NAME),)
$(error "No OS Kernelname? ('uname -s' failed) and nothing specified")
endif

# Version settings
SHAREDNAME = defiantclient
MAJOR_NO   = 1
MINOR_NO   = 0
RELEASE_NO = 1

LIBDEFIANTDIR=$(shell pwd)

# Libraries we need
LDLIBS += -lcurl -lssl -lcrypto -lz -lpbc -lgmp

DEPS += Makefile

# The shared objects
OBJS +=	defiantclient.o		\
	defiantrequest.o	\
	defiantrequest_curl.o	\
	makeargv.o		\
	cweb.o			\
	onion.o			\
	jpeg_steg.o		\
	nep.o			\
	utils.o			\
	defiantbf.o		\
	blobs.o			\
	crc.o			\
	defiantcookie.o		\
	defianterrors.o

# With leading ../ for tools+test directories
OBJST = $(shell echo ../$(OBJS) | sed 's/ / \.\.\//g')

CFLAGS += -g

# OS specifics
ifeq ($(OS_NAME),Darwin)
CFLAGS	+= -std=c99 -I
SHAREDLIB = $(SHAREDNAME).dylib
SHAREDLIBDIR = /opt/local/lib
else
ifeq ($(OS_NAME),Linux)
CFLAGS += -fPIC -D_BSD_SOURCE -DPATH_MAX=4096 -std=c99
SHAREDLIB = lib$(SHAREDNAME).so
SHAREDLIBDIR = /usr/local/lib
SHAREDARCHIVE = lib$(SHAREDNAME).a
else
ifeq ($(OS_NAME),Windows)
LDLIBS += -lgdi32 -lws2_32
CFLAGS += -D_BSD_SOURCE -DPATH_MAX=4096 -std=gnu99 -DCURL_STATICLIB
OBJS += platform.o
SHAREDLIB = lib$(SHAREDNAME).so
SHAREDLIBDIR =
SHAREDARCHIVE = lib$(SHAREDNAME).a
else
$(error "Unsupported OS: $(OS_NAME)")
endif # Windows
endif # Linux
endif # Darwin

CFLAGS += -Wall -pedantic -g

DEFAULT_LIB_INSTALL_PATH = .

# Remove '@' to get them to be verbose
COMPILE = @echo " * Compiling $@"; $(CC) -c $(CFLAGS)
SHARED  = @echo " * Shared $@"; $(CC) -shared $(LDFLAGS) -o $(SHAREDLIB)
LINK    = @echo " * Linking $@"; $(CC) $(CFLAGS) $(LDFLAGS)
RM	= @echo "== Removing..."; rm
ARCHIVE	= @echo "== Archiving $@"; $(AR)

export CC
export AR
export RM
export OS_NAME
export CFLAGS
export LDFLAGS
export LDLIBS
export OBJS
export OBJST
export OS_NAME
export COMPILE
export LINK
export LIBDEFIANTDIR

all: $(DEPS) $(OBJS) $(SHAREDLIB)
	@$(MAKE) -C tools
	@$(MAKE) -C tests

# Include all the dependencies
-include $(OBJS:.o=.d)

depend: clean
	@echo "* Making dependencies"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

%.o: %.c $(DEPS)
	@echo "* Compiling $@";
	@$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

$(SHAREDLIB): $(DEPS) $(SHAREDARCHIVE)
	@echo "==== Shared Library" 
ifeq ($(OS_NAME),Darwin)
	$(LINK) $(OBJS)  -dynamiclib -install_name $(LIBDEFIANTDIR)/defiantclient.dylib -o defiantclient.dylib -lc $(LDFLAGS) $(LDLIBS)
else
ifeq ($(OS_NAME),Linux)
	$(SHARED) $(OBJS) $(LDFLAGS) $(LDLIBS)
endif
endif
	@echo "==== Shared Library - done"

sharedobject_mac: $(DEPS)

$(SHAREDARCHIVE): $(DEPS)
	@echo "==== Archive"
	$(ARCHIVE) crs $(SHAREDARCHIVE) $(OBJS)

install:
#	cp $(SHAREDLIB}.$(MAJOR_NO).$(MINOR_NO).$(RELEASE_NO) $(SHAREDLIBDIR)
#	ldconfig -n $(SHAREDLIBDIR)

clean:
	@echo "==== Cleaning up..."
	$(RM) -f $(EXE) *.o $(SHAREDARCHIVE) $(SHAREDLIB) $(SHAREDLIB).* $(SHAREDNAME).a
	@$(MAKE) -C tools clean
	@$(MAKE) -C tests clean

reallyclean: clean
	@echo "==== Really cleaning up..."
	$(RM) -rf *.dSYM *~ *.bin

