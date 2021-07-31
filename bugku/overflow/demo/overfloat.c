#include<stdio.h>

int main()
{
    // char s[48]; // [rsp+0h] [rbp-30h] BYREF
    // memset(s, 0, sizeof(s));
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);
    vuln();
    return 0;
}
void vuln()
{
    char s[240];
    printf("s的地址:%p",s);
    read(0,s,248);
    printf("shurujieshu");
}

void backdoor()
{
    system("/bin/sh");
}