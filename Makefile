OPENSSL=../radius

CFLAGS=-O -Wall -I$(OPENSSL)/include -L$(OPENSSL)/lib

OBJS=miniradiusd.o md5.o hmac_md5.o
all: miniradiusd

miniradiusd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) -lcrypto -lssl
