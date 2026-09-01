APXS ?= $(shell command -v apxs2 || command -v apxs)

all: mod_auth_request.la

mod_auth_request.la: mod_auth_request.c
	$(APXS) -Wc,-Wall -c $<

install: mod_auth_request.la
	$(APXS) -i -n auth_request mod_auth_request.la

test: mod_auth_request.la
	./test/smoke.sh

clean:
	rm -rf .libs *.la *.lo *.slo *.o

.PHONY: all install test clean
