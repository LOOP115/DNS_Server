dns_svr: main.o socket.o tools.o
	gcc -Wall -o dns_svr main.o socket.o tools.o -g -lpthread

main.o: main.c
	gcc -Wall -c -o main.o main.c -g -lpthread

socket.o: socket.c socket.h
	gcc -Wall -c -o socket.o socket.c -g

tools.o: tools.c tools.h
	gcc -Wall -c -o tools.o tools.c -g

clean:
	rm -f dns_svr main.o socket.o tools.o
