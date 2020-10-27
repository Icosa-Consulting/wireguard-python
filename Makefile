# Makefile
DESTDIR     ?= ../dist
PYLIB       ?= libwg

WGDIR       = ../wireguard-tools/src
WGLIBDIR    = $(WGDIR)/build/$(CONF)
CSTD        = gnu99
CC	    = gcc
AR          = ar
ARFLAGS     = rcs

CFLAGS      ?= -fPIC -std=$(CSTD) -O3 -fstack-protector
CFLAGS      += -D_GNU_SOURCE
CFLAGS      += -Wall -Wextra
CFLAGS      += -MMD -MP

LDFLAGS	    = -L. -lc -shared
INCLUDES    = -Isrc

# BUILD environment
GITCOMMIT=$(shell git rev-list -1 HEAD)
NOW=$(shell date "+%Y%m%d%H%M")

# OBJ paths match their src folder equivalents
INCDIR  = include
OBJDIR  = build
SRCDIR  = src
LIBDIR  = lib
BINDIR  = shared
BIN     = $(BINDIR)/libwg.so
LIB	= $(LIBDIR)/$(LIBNAME).a
DISTDIR	= dist

OBJS    ?= $(OBJDIR)/config.o
OBJS    += $(OBJDIR)/wireguard.o
OBJS    += $(OBJDIR)/wglib.o

default: setup $(BIN)
	echo "Copying binaries to $(DESTDIR)"; \
	cp -uvr $(BINDIR) $(DESTDIR); \
	cp -uv $(SRCDIR)/$(PYLIB).py $(DESTDIR); \
	cp -uv $(SRCDIR)/$(PYLIB)so.py $(DESTDIR)/shared/

setup:
	mkdir -p $(BINDIR); \
	mkdir -p $(OBJDIR);

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJS);\
	checksec --format=cli --file=$(BIN)
	py3compile $(DESTDIR)

build/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(DISTDIR) $(OBJDIR) $(LIBDIR) $(OBJS) $(LIB) *~
	find . -name "*.o" -exec rm -f {} \;

fix-spaces:
	find . -name "*.c" -exec perl -pi -e 's/\( /\(/' {} \;
	find . -name "*.h" -exec perl -pi -e 's/\( /\(/' {} \;

format:
	clang-format -i src/*.c src/*.h
