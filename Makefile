CC	= gcc
CFLAGS = -pipe -g -Wall
LDFLAGS	= -lpthread
TARGET = ocat

all: $(TARGET)

ocat: ocatroute.o ocattun.o ocatv6conv.o

clean:
	rm -f *.o $(TARGET)

