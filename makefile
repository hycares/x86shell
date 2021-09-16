KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm
STDCPP = -std=c++1z

src = $(wildcard ./*.cpp)
target = app

all:
	${CC} -o $(target) $(src) ${KEYSTONE_LDFLAGS} $(STDCPP)

clean:
	rm -rf *.o $(target) 