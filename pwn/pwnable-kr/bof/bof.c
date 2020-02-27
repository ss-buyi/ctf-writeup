/*************************************************************************
    > File Name: bof.c
    > Author: amoscykl
    > Mail: amoscykl@163.com 
    > Created Time: Wed 13 Nov 2019 06:05:28 PM PST
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key)
{
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe)
	{
		system("/bin/sh");
	}
	else
	{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[])
{
	func(0xdeadbeef);
	return 0;
}

