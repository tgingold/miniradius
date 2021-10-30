OPENSSL=../radius

CFLAGS=-O -Wall -I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL)/lib -lcrypto -lssl

OBJS=miniradiusd.o dump.o md5.o hmac_md5.o

all: miniradiusd

miniradiusd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

.PHONY: clean

clean:
	$(RM) *.o miniradiusd *~
