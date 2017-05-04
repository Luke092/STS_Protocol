all: server.o client.o crypto.o encodings.o main.c
	cc -g -o sts -lssl -lcrypto server.o client.o crypto.o encodings.o main.c

server.o: server.c
	cc -c -g server.c

client.o: client.c
	cc -c -g client.c

crypto.o: crypto.c
	cc -c -g crypto.c

encodings.o: encodings.c
	cc -c -g encodings.c

clean:
	rm -f *.o
	rm -f sts
