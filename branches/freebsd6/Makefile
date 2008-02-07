CC	= gcc
#PREOPTS	= -DWITHOUT_TUN
CFLAGS = -pipe -g -Wall $(PREOPTS)
#LDFLAGS	= -lpthread -lrt
LDFLAGS	= -lpthread
TARGET = ocat

all: $(TARGET)

ocat: ocatroute.o ocattun.o ocatv6conv.o ocatlog.o

clean:
	rm -f *.o $(TARGET)

