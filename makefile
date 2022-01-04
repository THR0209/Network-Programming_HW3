all:
	gcc -g getpacket.c -o getpacket -lpcap

clean:
	rm getpacket
