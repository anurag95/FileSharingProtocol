CC = gcc
PROG = program

SRCS = network.c

LIBS = -lssl -lcrypto
all: $(PROG)

$(PROG):    $(SRCS)
    $(CC) -o $(PROG) $(SRCS) $(LIBS)

clean:
    rm -f $(PROG)
