CC      := gcc
CCFLAGS := -Wall -g -std=c11 -m64
LDFLAGS := -lm

TARGETS:= main
MAINS  := $(addsuffix .o, $(TARGETS) )
OBJ    := modele.o $(MAINS)
DEPS   := modele.h

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJ)

$(OBJ): %.o : %.c $(DEPS)
	$(CC) -c -o $@ $< $(CCFLAGS)

$(TARGETS): % : $(filter-out $(MAINS), $(OBJ)) %.o
	$(CC) -o $@ $(LIBS) $^ $(CCFLAGS) $(LDFLAGS)
