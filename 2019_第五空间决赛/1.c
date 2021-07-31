#include<stdio.h>
int main()
{
	int fd;
	fd = open("/dev/urandom", 0);
	printf("%x",fd);
	return 0;
}
