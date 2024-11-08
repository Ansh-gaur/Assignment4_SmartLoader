#Compile the launch.c by linking it with the lib_simpleloader.so
all:  
	
	gcc -m32 -L../bin -Wl,-rpath=../bin -o launch launch.c -l_simpleloader && mv launch ../bin/
clear:
