# Rendezvous Makefile

# Always try one directory up and local includes
CFLAGS += -I../ -I/usr/local/include/
LDFLAGS += -L/usr/local/lib/

export CFLAGS
export LDFLAGS

all: everything

deb:
	@echo "== Building Debian Package... (requires 'dpkg-dev build-essential')"
	@dpkg-buildpackage -b

everything: client tools freedom server
	@echo "== Done with everything"

client:
	@echo "== Making Rendezvous Client (client/src)"
	@$(MAKE) -C client/src

tools:
	@echo "== Making Rendezvous Client Tools (client/tools/captcha)"
	@cd client/tools/captcha; ant

freedom:
	@echo "== Making Freedom"
	@$(MAKE) -C freedom

server:
	@echo "== Making OnionFactory/Server"
	@$(MAKE) -C onionfactory/server

clean:
	@echo "=== Cleansing..."
	@$(MAKE) -C client/src clean
	cd client/tools/captcha; ant clean
	@$(MAKE) -C freedom clean
	@$(MAKE) -C onionfactory/server clean
	if [ -f outguess/Makefile ]; then $(MAKE) -C outguess distclean; fi
	@echo "=== Cleanse complete"

win:
	@./cross-compile

.PHONY: client tools freedom server clean win

