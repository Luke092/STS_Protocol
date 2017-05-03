all: server.o client.o crypto.o main.c
	cc -o sts -lssl -lcrypto server.o client.o crypto.o main.c

server.o: server.c
	cc -c server.c

client.o: client.c
	cc -c client.c

crypto.o: crypto.c
	cc -c crypto.c

clean:
	rm -f *.o
	rm -f sts
