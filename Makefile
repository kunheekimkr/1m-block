LDLIBS=-lnetfilter_queue

all: 1m-block

main.o: main.cpp libnet.h trie.h

trie.o : trie.h trie.cpp

1m-block: main.o trie.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f 1m-block *.o
