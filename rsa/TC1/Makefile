CC = gcc
LIB:= -L/usr/local/lib -lcrypto
OPENSSL_RSAPUBKEY :=1

SUBDIR = .
SRCS = $(wildcard $(SUBDIR)/*.c)
OBJS = $(SRCS:.c = $(SUBDIR)/.o)

CCFLAGS := -Wall -O2 -g
CCFLAGS += -DRSAPUBKEY
TARGET = openssl_rsa_tc1

$(TARGET):$(OBJS)
	$(CC) $^ $(CCFLAGS) $(LIB) -o $@

%.o : %.c
	$(CC) $(CCFLAGS) -c $<

clean:
	rm -fr $(TARGET) *.o $(SUBDIR)/*.o
