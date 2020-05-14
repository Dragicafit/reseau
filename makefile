CC      := gcc
CCFLAGS := -Wall -g -std=c11 -m64 $(shell pkg-config --cflags glib-2.0)
LDFLAGS := -lm -lcrypto $(shell pkg-config --libs glib-2.0)

TARGETS:= main
MAINS  := $(addsuffix .o, $(TARGETS) )
OBJ    := $(patsubst %.c, %.o, $(wildcard *.c))
DEPS   := $(wildcard *.h)

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJ)

$(OBJ): %.o : %.c $(DEPS)
	$(CC) -c -o $@ $< $(CCFLAGS)

$(TARGETS): $(OBJ)
	$(CC) -o $@ $(LIBS) $^ $(CCFLAGS) $(LDFLAGS)
