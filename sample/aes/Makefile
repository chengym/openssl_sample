CC = gcc
LIB:= -L/usr/local/lib -lcrypto

SUBDIR = .
SRCS = $(wildcard $(SUBDIR)/*.c)
OBJS = $(SRCS:.c = $(SUBDIR)/.o)

CCFLAGS = -Wall -O2
TARGET = openssl_aes

$(TARGET):$(OBJS)
	$(CC) $^ $(CCFLAGS) $(LIB) -o $@

%.o : %.c
	$(CC) $(CCFLAGS) -c $<

clean:
	rm -fr $(TARGET) *.o $(SUBDIR)/*.o
