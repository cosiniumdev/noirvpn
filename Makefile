# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

ODIN      ?= odin
COLL      := -collection:noir=$(CURDIR)
TESTFLAGS ?= -vet -strict-style
TESTOUT   := out/test
# The CPU level of the build: x86-64-v3 on amd64. NOIR_MICROARCH selects
# another level (see build/microarch.sh).
ARCHFLAGS := $(shell build/microarch.sh)

# macOS: nng 1.x is built by build/macos-nng.sh into out/macos/nng (Homebrew has
# only nng 2.x) and bus/nng links that file by its path. OpenSSL comes from Homebrew.
ifeq ($(shell uname -s),Darwin)
TEST_DEPS := macos-nng
BREW_LIB  := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)/lib
LINKFLAGS ?= -extra-linker-flags:"-L$(BREW_LIB)"
# noirvpn-hook starts commands with fork and execve system calls: Linux only.
NOT_ON_THIS_OS := cmd/noirvpn-hook/
endif

# Every directory below these roots that has a *_test.odin file. A top-level
# folder with a test.mk can add roots to TEST_ROOTS, and targets that `make test`
# runs after the packages to TEST_EXTRA.
TEST_ROOTS := proto platform bus server client engine cmd
TEST_EXTRA :=
.DEFAULT_GOAL := test
-include $(wildcard */test.mk)
TEST_PKGS := $(filter-out $(NOT_ON_THIS_OS),$(sort $(dir $(shell find $(TEST_ROOTS) -name '*_test.odin' 2>/dev/null))))

# Test binaries go under out/ (gitignored), so a killed run leaves nothing in
# the repo root.
.PHONY: test
test: $(TEST_DEPS)
ifdef PKG
	@mkdir -p $(TESTOUT)
	$(ODIN) test $(PKG) $(COLL) $(TESTFLAGS) $(ARCHFLAGS) $(LINKFLAGS) -out:$(TESTOUT)/$(subst /,_,$(patsubst %/,%,$(PKG))).bin
else
	@mkdir -p $(TESTOUT); set -e; for p in $(TEST_PKGS); do echo "== $$p"; \
		$(ODIN) test $$p $(COLL) $(TESTFLAGS) $(ARCHFLAGS) $(LINKFLAGS) -out:$(TESTOUT)/$$(echo $${p%/} | tr / _).bin; done
ifneq ($(TEST_EXTRA),)
	@$(MAKE) --no-print-directory $(TEST_EXTRA)
endif
endif

# The option reference of the user documentation, from the option table.
.PHONY: docs
docs:
	@mkdir -p out
	$(ODIN) run build/gen-options-doc $(COLL) -out:out/gen-options-doc > docs/options.md

# The programs of this system, with libraries and licence texts, in
# dist/<os>-<arch>/ (see build/README.md). DIST_FLAGS=--static on Linux.
.PHONY: dist
dist:
	build/dist.sh $(DIST_FLAGS)

# macOS: the static nng 1.x that the programs link (see build/macos-nng.sh).
.PHONY: macos-nng
macos-nng:
	build/macos-nng.sh

# The Windows installer from dist/windows-amd64/, in dist/ (see build/README.md).
.PHONY: msi
msi:
	build/msi.sh
