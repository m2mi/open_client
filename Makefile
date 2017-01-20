OPENSSL_INCLUDE = -I/Users/julien/Documents/M2Mi/openssl/include/
OPENSSL_LIB = -L/Users/julien/Documents/M2Mi/openssl/lib/
#OPENSSL_INCLUDE = -I/usr/local/opt/openssl/include
#OPENSSL_LIB = -L/usr/local/opt/openssl/lib


CFLAGS=-Wall -g $(OPENSSL_INCLUDE)
LDFLAGS=$(OPENSSL_LIB) -lcrypto -lssl

SOURCES=$(wildcard src/main/c/*.c)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

TARGET=bin/https

all: $(TARGET)

$(TARGET): build $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

build:
	@mkdir -p bin

dev:CFLAGS+=-DNDEBUG
dev: all

clean:
	rm -rf bin/https src/main/c/*.o
