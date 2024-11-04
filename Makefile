CC := gcc
WINDOWSCC := x86_64-w64-mingw32-gcc
CFLAGS := -ggdb

main: main.o
	$(CC) $(CFLAGS) -o $@ $^
	./main

main.exe: main.c
	$(WINDOWSCC) -o $@ $^ $(CFLAGS)
	
build: main.o
	$(CC) $(CFLAGS) -o ./main $^

%.o: %.c
	$(CC) -o $@ $< -c
	
clean:
	rm -rf main *.o *.exe
