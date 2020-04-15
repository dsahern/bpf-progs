CC = gcc
CFLAGS = -O2 -g -Wall

PROGS := socktest

all: $(PROGS)

%: %.c
	$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	@rm -f $(PROGS)
