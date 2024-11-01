CC := gcc
CFLAGS := -O3

main: main.o
	$(CC) $(CFLAGS) -o $@ $^
	./main

%.o: %.c
	$(CC) -o $@ $< -c
	
clean:
	rm -rf main *.o
