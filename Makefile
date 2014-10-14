#Makefile
CC = gcc
INCLUDE = /usr/lib
LIBS = -lcrypto -lssl
OBJS = 
CFLAGS = 

all: clean echoClient echoServer

echoServer: 
	$(CC) -o echoServer echoServer.c $(CFLAGS) $(LIBS)
echoClient:
	$(CC) -o echoClient echoClient.c $(CFLAGS) $(LIBS)

clean:
	rm -f echoClient echoServer
