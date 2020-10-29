//gcc -static pwn.c -o pwn -l seccomp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <string.h>

int read_num(char *str){
    int count = 1;
    char buf = 0;
    int str_len = 0;
    while(count){
        int read_res = read(0,&buf,1);
        if(buf == '\n' || read_res == -1 || str_len == 0xc0){
            count = 0;
        }
        else{
            *(str+str_len) = buf;
            str_len += 1;
        }
    }
    return 0;
}

int main(){
    
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(open),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(read),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(mprotect),0);
    seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0);
    seccomp_load(ctx);

    printf("Input your message,it will echo back.\n");

    char input[0xc0];
    memset(input,0,0xc0);
    read_num(input);

    printf("Take your message:\n");
    printf(input);

    return 0;
}
