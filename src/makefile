CC=gcc
CFLAGS=-O3 -std=c99
TARGET=turtle
all: $(TARGET)

$(TARGET): turtle_crypt_cbc.c
	$(CC) turtle_crypt_cbc.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
