CC = gcc
CFLAGS   = 
LDFLAGS  = -lcrypto -lssl
LDFLAGS += -Wl,-rpath -Wl,./protobuf-c/out/lib -lprotobuf-c
LDFLAGS += -L./jsmn -ljsmn

all: chrome

%.o: %.c
	$(CC) -c $< $(CFLAGS)

%.pb-c.c: %.proto
	./protobuf-c/out/bin/protoc-c -I. --c_out . $<

main.o:		CFLAGS += -I./jsmn/
chrome.o: 	CFLAGS += -I./jsmn/
castd.o: 	CFLAGS += -I./jsmn/

chrome: cast_channel.pb-c.o mdns.o chrome.o main.o
	$(CC) -o $@ $^ $(LDFLAGS)

castd: cast_channel.pb-c.o mdns.o chrome.o castd.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o chrome castd mdns

.PHONY: clean
