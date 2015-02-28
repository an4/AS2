attack       : $(wildcard attack.[ch])
	@gcc -Wall -std=gnu99 -m64 -O3 -o ${@} $(filter %.c, ${^})

clean :
	@rm -f attack
