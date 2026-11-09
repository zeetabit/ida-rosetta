# Universal (arm64 + x86_64) build of the ASLR-disabling launcher.
# On Apple Silicon `noaslr` runs natively; an x86_64 caller still works
# because the target itself is spawned by the kernel/Rosetta.

CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra
ARCHS   ?= arm64 x86_64
MINOS   ?= 11.0
TARGET  ?= noaslr
ARCHFLAGS = $(foreach a,$(ARCHS),-arch $(a))

all: $(TARGET)

$(TARGET): noaslr.c
	$(CC) $(CFLAGS) $(ARCHFLAGS) -mmacosx-version-min=$(MINOS) -o $@ $<
	@lipo -info $@ || true

clean:
	rm -f $(TARGET)

.PHONY: all clean
