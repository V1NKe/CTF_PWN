#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/mman.h>

uint64_t base;
char *log_addr;

uint32_t read_num(){
    char s[0x10];
    memset(&s,0,0x10);
    read(0,&s,0x10);
    return atoi(s);
}

void menu(){
   puts("======================\n");
   puts("1.Edit your paper");
   puts("2.Delete some line");
   puts("3.Print paper");
   puts("4.Exit\n");
   puts("======================");
   printf("Input your choice:");
}

void edit(){
    printf("Input the offset :");
    uint32_t offset = read_num();
    printf("Input the length :");
    uint32_t len = read_num();
    if(offset > 0xFFFF || len > 0xFFFF || (offset + len) > 0xFFFF){
        puts("Invaild offset or length!");
        exit(0);
    }
    printf("Input the content :");
    read(0,(uint32_t *)(base + offset),len);
    puts("Good!");
    return ;
}

void del(){
    printf("Input the offset :");
    uint32_t offset = read_num();
    if(offset > 0xFFFF){
        puts("Invaild offset!");
        exit(0);
    }
    free((uint32_t *)(base + offset));
    puts("Good!");
    return ;
}

void log_(){
    if(log_addr){
        puts("Only once.");
    }
    else{
        log_addr = (char *)malloc(0x138);
    }
    puts("Good!");
    return ;
}

void exit_(){
    if(log_addr){
        printf("%s",strdup(log_addr));
    }
    exit(0);
}

void pwn(){
    puts("It's a printer,try to print paper.");
    while(1){
        menu();
        int choice = read_num();
        switch(choice){
            case 1:
                edit();
                break;
            case 2:
                del();
                break;
            case 3:
                log_();
                break;
            case 4:
                exit_();
                break;
            default:
                puts("Something Wrong..");
        }
    }
    return;
}

void init(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
    alarm(0x5c);
    int fd = open("/dev/urandom",0);
    read(fd,&base,8);
    //base = 0x23330000;
    base = base & 0xFFFFF000;
    close(fd);
    if((uint32_t *)mmap((void *)base,0x1000,3,0x22,-1,0) != (uint32_t *)base){
        puts("MMAP ERROR!");
        exit(1);
    }
    sleep(0);
    //printf("0x%lx\n",(uint64_t)&sleep);
    printf("0x%lx\n",((uint64_t)&sleep & 0xFFF00) >> 8);
    malloc(0);
    return ;
}

int main(){
    init();
    pwn();
    return 0;
}
