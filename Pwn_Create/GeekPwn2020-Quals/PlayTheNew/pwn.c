//gcc pwn.c bpf-helper.c util.c -o pwn 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/mman.h>
#include <string.h>

typedef struct chunk{
    char *chunk_ptr;
    uint32_t chunk_size;
} chunk;

chunk chunk_[5];

uint64_t *mmap_addr;

void io_init(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
    //alarm(0x5c);
    mmap_addr = (uint64_t *)mmap((void*)0x100000,0x1000,3,34,-1,0);
    *mmap_addr = 0x42;
}

int read_(){
    char buf[8];
    read(0,&buf,8);
    int read_num = atoi(buf);
    return read_num;
}

void menu(){
    puts("* Buy a basketball"); //add
    puts("* Throw a basketball");//delete
    puts("* Show a dance");//show
    puts("* Change a basketball");//edit
    printf("> ");
}

void add(){
    int idx = 0;
    printf("Input the index:");
    idx = read_();
    if(idx > 4 || idx < 0){
        puts("Invaild idx!");
	exit(0);
    }
    else{
    	printf("input the size of basketball:");
	int chunk_size = read_();
	if(0x80 < chunk_size && chunk_size <= 0x200){
	    chunk_[idx].chunk_ptr = (char *)calloc(1,chunk_size);
	}
	else{
	    //puts("Out of bounds!");
	    exit(0);
	}
	chunk_[idx].chunk_size = chunk_size;
	if(chunk_[idx].chunk_ptr){
	    printf("Input the dancer name:");
	    read(0,chunk_[idx].chunk_ptr,chunk_[idx].chunk_size);
	    puts("Success!");
	}
	else{
	    chunk_[idx].chunk_ptr = 0;
	    chunk_[idx].chunk_size = 0;
	}
    }
    return ;
}

void delete(){
    printf("Input the idx of basketball:");
    int idx = read_();
    if(idx > 4 || idx < 0){
        puts("Invaild idx!");
	exit(0);
    }
    if(!chunk_[idx].chunk_ptr){
        puts("No basketball.");
	exit(0);
    }
    free(chunk_[idx].chunk_ptr);  //UAF
    //chunk_[idx].chunk_ptr = 0;
    //chunk_[idx].chunk_size = 0;
}

void show(){
    printf("Input the idx of basketball:");
    int idx = read_();
    if(idx < 0 || idx > 4){
        puts("Invaild idx!");
        exit(0);
    }
    if(!chunk_[idx].chunk_ptr){
        puts("No basketball.");
        exit(0);
    }
    printf("Show the dance:");
    //write(1,chunk_[idx].chunk_ptr,chunk_[idx].chunk_size);
    //printf("\n");
    puts(chunk_[idx].chunk_ptr);
}

void edit(){
    printf("Input the idx of basketball:");
    int idx = read_();
    if(idx < 0 || idx > 4){
        puts("Invaild idx!");
        exit(0);
    }
    if(!chunk_[idx].chunk_ptr){
        puts("No basketball.");
        exit(0);
    }
    printf("The new dance of the basketball:");
    read(0,chunk_[idx].chunk_ptr,chunk_[idx].chunk_size);
}

void mmap_write(){
    if(*mmap_addr == 0x42){
        exit(0);
    }
    printf("Input the secret place:");
    if(read(0,mmap_addr+1,0x148) <= 0){
    	exit(0);
    }
}

void trigger_func(){
    //void (*shell)() = (void(*)())mmap_addr;
    //shell(*(mmap_addr+6));
    if(*mmap_addr == 0x42){
    	exit(0);
    }
    void (*shell)() = (void(*)())*(mmap_addr+2);
    //shell();
    shell(*(mmap_addr+3));
}

int main(){
    io_init();
    puts("It's your show time!\n");
    while(1){
        menu();
        int case_num = read_();
        switch(case_num){
            case 1 :
	        add();
                break;
	    case 2 :
                delete();
	        break;
	    case 3 :
                show();
	        break;
	    case 4 :
                edit();
	        break;
	    case 5 :
                mmap_write();
	        break;
	    case 0x666 :
                trigger_func();
	        break;
	    default :
                exit(0);
	        break;
        }
    }

    return 0;
}
