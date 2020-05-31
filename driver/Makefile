CC      = gcc
CFLAGS  = -O0 -g3 -fno-omit-frame-pointer
LDFLAGS =

EXES = driver

driver: driver.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o driver driver.c

clean:
	rm -f $(EXES) *.o
