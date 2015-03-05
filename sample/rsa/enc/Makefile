CC = gcc
RM := rm -fr

SUBDIR = .
SRCS = $(wildcard $(SUBDIR)/*.c)
OBJS = $(SRCS:.c = $(SUBDIR)/.o)

CCFLAGS = -Wall -O2
LIB:= -lcrypto
TARGET = openssl_rsa_enc

$(TARGET):$(OBJS)
	@$(CC) $^ $(CCFLAGS) $(LIB) -o $@

%.o : %.c
	@$(CC) $(CCFLAGS) -c $<

clean:
	@$(RM) $(TARGET) *.o
