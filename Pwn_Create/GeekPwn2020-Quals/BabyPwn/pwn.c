//gcc -z now -fPIC -pie pwn.c -o pwn
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

typedef struct Member{
    char name[0x20];
    char *description;
} member;

member member_len[10];

void init(){
    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    alarm(0x5c);
}

void menu(){
   puts("======================\n");
   puts("1.Add a member");
   puts("2.Throw out");
   puts("3.Show the member");
   puts("4.Exit\n");
   puts("======================");
   printf("Input your choice:");
}

void read_(uint8_t *addr,int size){
    int count = 0;
    char buf;
    int count_;
    while(1){
        unsigned int size_ = (unsigned int)(size - 1);
        if(size_ <= count){
            break;
        }
        read(0,&buf,1);
        if(buf == '\n'){
            break;
        }
        count_ = count++;
        *((uint8_t *)addr + count_) = buf;
    }
}

void add(){
    int idx = 0;
    while(idx <=9 && member_len[idx].description){
        idx += 1;
    }
    if(idx >= 10){
        puts("Member is full!");
    }
    else{
        printf("Member name:");
        read_(member_len[idx].name,0x20);
        printf("Description size:");
        int size;
        scanf("%u",&size);
        if(size < 0 || size > 0x40){
            puts("It's tooooooooo large!");
            exit(0);
        }
        member_len[idx].description = (char*)malloc(size);
        if(!member_len[idx].description){
            puts("Malloc error!");
            exit(0);
        }
        printf("Description:");
        read_(member_len[idx].description,size);
        puts("OK!");
    }
    return;
}

void delete(){
    printf("index:");
    int index;
    scanf("%u",&index);
    if(index > 9){
        puts("invalid index!");
        exit(0);
    }
    if(!member_len[index].description){
        puts("No member!");
        exit(0);
    }
    free(member_len[index].description);
    member_len[index].description = 0;
    return;
}

void show(){
    printf("index:");
    int index;
    scanf("%u",&index);
    if(index > 9){
        puts("invalid index!");
        exit(0);
    }
    if(!member_len[index].description){
        puts("No member!");
        exit(0);
    }
    printf("The name:%s\nThe Description:%s\n",member_len[index].name,member_len[index].description);
}

void babyheap(){
    puts("Welcome to the club!");
    char s[0x10];
    while(1){
        menu();
        memset(&s,0,0x10);
        read(0,&s,0x10);
        int choice = atoi(s);
        switch(choice){
            case 1:
                add();
                break;
            case 2:
                delete();
                break;
            case 3:
                show();
                break;
            case 4:
                puts("Goodbye~");
                exit(0);
            default:
                puts("Something Wrong..");
        }
    }
    return;
}
int main() {
    init();
    babyheap();
    return 0; 
}
