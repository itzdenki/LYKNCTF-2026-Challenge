CC      ?= gcc
CFLAGS  ?= -O2 -fwrapv -Wall
TARGET   = dist/shop

# On Windows/MSYS gcc produces dist/shop.exe; the plain name works too.
all: $(TARGET)

$(TARGET): shop.c
	mkdir -p dist
	$(CC) $(CFLAGS) -o $(TARGET) shop.c

clean:
	rm -f $(TARGET) $(TARGET).exe

.PHONY: all clean
