LDLIBS=-lpcap

all: airodump

airodump: main.o
	g++ $^ $(LDLIBS) -g -o $@

clean:
	rm -rf airodump *.o
