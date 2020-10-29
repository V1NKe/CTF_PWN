/*
 * BabyPwn.c
 * Copyright (C) 2019 V1NKe <v1nke@tom.com>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct Member{
    char name[16];
    char *description;
    int description_size;
} member;

member *member_len[10];

void init(){
    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    alarm(0x5c);
}

void menu(){
   puts("======================\n");
   puts("1.Add a member");
   puts("2.Throw him out");
   puts("3.Exit\n");
   puts("======================");
   printf("Input your choice:");
}

int read_(){
    char *buf[4];
    read(0,buf,4);
    return atoi(buf);
}

void add(){
    int idx = 0;
    while(idx <=9 && member_len[idx]){
        idx += 1;
    }
    if(idx >= 10){
        puts("Member is full!");
    }
    else{
        member_len[idx] = (member*)malloc(0x20);
        if(!member_len[idx]){
            puts("Malloc error!");
            exit(0);
        }
        printf("Member name:");
        read(0,member_len[idx]->name,0x10);
        printf("Description size:");
        int size;
        size = read_();
        if(size < 0 || size > 0xff){
            puts("It's tooooooooo large!");
            exit(0);
        }
        member_len[idx]->description_size = size;
        member_len[idx]->description = (char*)malloc(size);
        if(!member_len[idx]->description){
            puts("Malloc error!");
            exit(0);
        }

        printf("Description:");
        read(0,member_len[idx]->description,size);
        puts("OK!");
    }
    return;
}

void delete(){
    printf("index:");
    int index;
    index = read_();
    if(index > 9){
        puts("invalid index!");
        exit(0);
    }
    free(member_len[index]->description);
    return;
}

void babyheap(){
    
    puts("Welcome to N1CTF2019!");
    puts("Now that you are the leader of Nu1L Team.");
    puts("Do you wanna manage your team?");
    puts("Maybe you can do anything what you want..");
    int choice;
    while(1){
        menu();
        choice = read_();
        switch(choice){
            case 1:
                add();
                break;
            case 2:
                delete();
                break;
            case 3:
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