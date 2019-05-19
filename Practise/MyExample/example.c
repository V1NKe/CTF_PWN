#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void){
	char* s = malloc(0x20);
	read(0, s, 0x18);
	write(1, s, 0x18);
	return 0;
}
