ifdef DEBUG
  CFLAGS += -DDEBUG
endif

all: symasan-mutator.so

CFLAGS	+= -O3 -funroll-loops

symasan-mutator.so: symasan.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -g -I../../include -shared -fPIC -o symasan-mutator.so symasan.c

clean:
	rm -f symasan.so *.o *~ core
