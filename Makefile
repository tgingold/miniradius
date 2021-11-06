OPENSSL=../radius

CFLAGS=-O -Wall -I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL)/lib -lcrypto -lssl

OBJS=miniradiusd.o dump.o hmac_md5.o config-static.o

all: miniradiusd

miniradiusd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

miniradiusd.o: dump.h radius.h config.h
config-static.o: config.h
dump.o: dump.h radius.h

.PHONY: clean

clean:
	$(RM) *.o miniradiusd *~
