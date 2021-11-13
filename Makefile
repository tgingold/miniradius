OPENSSL=../radius

CFLAGS=-O -Wall -I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL)/lib -lcrypto -lssl

OBJS=miniradiusd.o dump.o hmac_md5.o mschapv2.o config-static.o

all: miniradiusd

miniradiusd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

miniradiusd.o: dump.h radius.h mschapv2.h config.h
config-static.o: config.h
dump.o: dump.h radius.h
mschapv2.o: mschapv2.h

test_mschap2: test_mschap2.o dump.o mschapv2.o
	$(CC) -o $@ $(CFLAGS) $< dump.o mschapv2.o $(LDFLAGS)

.PHONY: clean

clean:
	$(RM) *.o miniradiusd *~
