# Specify the target
all: main

# Specify the object files that the target depends on
# Also specify the object files needed to create the executable

main: Main.o RC6.o
	g++ Main.o RC6.o -o main

# Specify how the object files should be created from source files
Main.o: Main.cpp
	g++ -c Main.cpp
RC6.o: RC6.cpp
	g++ -c RC6.cpp

# Specify the object files and executables that are generated
# and need to be removed to re-compile the whole thing
clean:
	rm -f *.o main
