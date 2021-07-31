#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
using namespace std;
char * GetMemory()
{
    char p[] = "hell oword";
	return p;
}
void Test()
{	
	char*str=NULL;
	str = GetMemory();
	cout<<str<<endl;
}

int main()
{
    Test();
    return 0;
}