CPP=g++
CFLAGS = -g -w

main:EcoCAM.cpp
	${CPP} ${CFLAGS} -o EcoCAM EcoCAM.cpp trie.cpp
all:EcoCAM
clean:
	rm EcoCAM.cpp
	
	
