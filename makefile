LIB=-Wall -lpcap
CCPP=g++

all: dipperview

dipperview:
	$(CCPP) dipperview.cpp -o dipperview $(LIB)

clean: 
	rm -f dipperview
