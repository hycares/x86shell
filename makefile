CC = g++

STDCPP = -std=c++1z
LDFLAGS = -lkeystone -lunicorn -lm -lpthread

SRC = $(wildcard ./*.cpp)

target = x86shell

all:
	$(CC) -o $(target) $(SRC) $(LDFLAGS) $(STDCPP)

debug:
	$(CC) -o $(target) $(SRC) $(LDFLAGS) $(STDCPP) -g

clean:
	rm -rf *.o $(target) 