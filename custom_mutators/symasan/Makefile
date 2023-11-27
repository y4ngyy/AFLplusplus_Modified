ifdef DEBUG
  CFLAGS += -DDEBUG
endif

all: symasan-symcc-mutator.so symasan-symsan-mutator.so

CFLAGS	+= -O3 -funroll-loops

symasan-symcc-mutator.so: symasan-symcc.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -g -I../../include -shared -fPIC -o symasan-symcc-mutator.so symasan-symcc.c

symasan-symsan-mutator.so: symasan-symsan.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -g -I../../include -shared -fPIC -o symasan-symsan-mutator.so symasan-symsan.c

clean:
	rm -f symasan-symcc-mutator.so symasan-symsan-mutator.so *.o *~ core
