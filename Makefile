CC := gcc
CFLAGS := -ggdb

main: main.o
	$(CC) $(CFLAGS) -o $@ $^
	./main
	
build: main.o
	$(CC) $(CFLAGS) -o ./main $^

%.o: %.c
	$(CC) -o $@ $< -c
	
clean:
	rm -rf main *.o
