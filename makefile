CC = g++

KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm
UNICORN_LDFLAGS = -lm -lunicorn -lpthread

STDCPP = -std=c++1z
LDFLAGS = -lkeystone -lunicorn -lm -lpthread
# src = $(wildcard ./*.cpp)

target = asmshell

keystonetarget = keytest
unicorntarget = unitest

all:
	$(CC) -o $(target) asmshell.cpp $(LDFLAGS) $(STDCPP)

debug:
	$(CC) -o $(target) asmshell.cpp $(LDFLAGS) $(STDCPP) -g

keystone:
	$(CC) -o $(keystonetarget) keystone_wrap_test.cpp ${KEYSTONE_LDFLAGS} $(STDCPP)

unicorn:
	$(CC) -o $(unicorntarget) unicorn_wrap_test.cpp $(UNICORN_LDFLAGS) $(STDCPP)

clean:
	rm -rf *.o $(target) 