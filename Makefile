CC	= gcc
#PREOPTS	= -DWITHOUT_TUN
CFLAGS = -pipe -g -Wall $(PREOPTS)
LDFLAGS	= -lpthread -lrt
TARGET = ocat

all: $(TARGET)

ocat: ocatroute.o ocattun.o ocatv6conv.o ocatlog.o ocatthread.o

clean:
	rm -f *.o $(TARGET)

install:
	install $(TARGET) /usr/local/bin

