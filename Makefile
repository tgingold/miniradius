OPENSSL=../radius

CFLAGS=-O -Wall -I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL)/lib -lcrypto -lssl

OBJS=miniradiusd.o dump.o hmac_md5.o users-static.o

all: miniradiusd

miniradiusd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

miniradiusd.o: dump.h radius.h users.h
users-static.o: users.h
dump.o: dump.h radius.h

.PHONY: clean

clean:
	$(RM) *.o miniradiusd *~
