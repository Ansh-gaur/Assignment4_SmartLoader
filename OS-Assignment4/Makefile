#invoke make inside following directories and in this order: loader, launch, fib
all:
	cd test && make && cd .. && cd loader && make && cd .. && cd launcher && make && cd ..
#Provide the command for cleanup
clean:
	$(MAKE) -C test clean
	rm -f bin/*
