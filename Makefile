CC = gcc
CFLAGS = -g  -I.
SOURCES = main.c url_query.c url.c 

all: att

#att:
#	$(CC) $(CFLAGS) $(SOURCES) -o att -lssl -lcrypto

att:
	gcc $(CFLAGS) http-client.c att2.c -o att -lssl -lcrypto -lpthread

.PHONY: clean

clean:
	rm -rf ./att ./*.o