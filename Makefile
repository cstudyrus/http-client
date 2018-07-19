CC = gcc
CFLAGS = -g  -I.
SOURCES = main.c url_query.c url.c 

all: att

att:
	$(CC) $(CFLAGS) $(SOURCES) -o att -lssl -lcrypto

.PHONY: clean

clean:
	rm -rf ./att 