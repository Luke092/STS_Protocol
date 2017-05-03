all: server.o client.o main.c
	cc -o sts server.o client.o main.c

server.o: server.c
	cc -c server.c

client.o: client.c
	cc -c client.c

clean:
	rm -f *.o
	rm -f sts
