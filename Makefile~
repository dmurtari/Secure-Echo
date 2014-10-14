#Makefile
CC = g++
INCLUDE = /usr/lib
LIBS = 
OBJS = 
CFLAGS = -fpermissive -Wno-write-strings

all: chat_server chat_coordinator chat_client

chat_server: 
	$(CC) -o chat_server chat_server.cc $(CFLAGS) $(LIBS)
chat_coordinator:
	$(CC) -o chat_coordinator chat_coordinator.cc $(CFLAGS) $(LIBS)
chat_client:
	$(CC) -o chat_client chat_client.cc $(CFLAGS) $(LIBS)

clean:
	rm -f chat_server chat_coordinator chat_client
