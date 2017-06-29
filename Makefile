all: server.o client.o crypto.o encodings.o peer.o sts_protocol.o logging.o main.c
	cc -o sts -lssl -lcrypto server.o client.o crypto.o encodings.o peer.o sts_protocol.o logging.o main.c

server.o: server.c
	cc -c server.c

client.o: client.c
	cc -c client.c

crypto.o: crypto.c
	cc -c crypto.c

encodings.o: encodings.c
	cc -c encodings.c

peer.o: peer.c
	cc -c peer.c

sts_protocol.o: sts_protocol.c
	cc -c sts_protocol.c

logging.o: logging.c
	cc -c logging.c

clean:
	rm -f *.o
	rm -f sts
