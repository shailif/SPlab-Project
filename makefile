all: task3

task3: task3.o
	gcc -g -m32 -o task3 task3.o
task3.o: task3.c
	gcc -g -m32 -c -o task3.o task3.c


.PHONY: clean
clean:
	rm -rf ./*.o task3 task3.o

