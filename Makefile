CC := gcc
WINDOWSCC := x86_64-w64-mingw32-gcc
CFLAGS := -ggdb

main: main.o
	$(CC) $(CFLAGS) -o $@ $^
	./main test_files/ProjectTrace.pcapng

main.exe: main.c
	$(WINDOWSCC) -o $@ $^ $(CFLAGS)
	
build: main.o
	$(CC) $(CFLAGS) -o ./main $^

%.o: %.c
	$(CC) -o $@ $< -c

debug: main.c
	$(CC) -g -o $@ $^

	
clean:
	rm -rf main *.o *.exe
