OPENSSL_INCLUDE = -I/Users/julien/Documents/M2Mi/openssl/include/
OPENSSL_LIB = -L/Users/julien/Documents/M2Mi/openssl/lib/

CFLAGS=-Wall -g $(OPENSSL_INCLUDE)
LDFLAGS=$(OPENSSL_LIB) -lcrypto -lssl

SOURCES=$(wildcard src/main/c/*.c src/main/c/**/*.c)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

TARGET=bin/m2mi

all: $(TARGET)

$(TARGET): build $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

build:
	@mkdir -p bin

dev:
	CFLAGS+=-DNDEBUG
dev: all

clean:
	rm -rf bin/m2mi src/main/c/*.o src/main/c/**/*.o
