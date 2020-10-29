//gcc -static pwn.c -o pwn
//exe user should be 1000
//bin/bash and pwn file should be setcap
//sudo setcap cap_setgid,cap_setuid+ep ./pwn

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#define STACK_SIZE (1024 * 1024)
 
char container_stack[STACK_SIZE];

//char* const bin[] = {
//    "/bin/bash",
//    NULL
//};

int pipefd[2];

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

void set_map(char* file, int inside_id, int outside_id, int len) {
    FILE* mapfd = fopen(file, "w");
    if (NULL == mapfd) {
        perror("error.");
        return;
    }
    fprintf(mapfd, "%d %d %d", inside_id, outside_id, len);
    fclose(mapfd);
}
 
void set_uid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/uid_map", pid);
    set_map(file, inside_id, outside_id, len);
}
 
void set_gid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/gid_map", pid);
    set_map(file, inside_id, outside_id, len);
}

int child_func(){
    alarm(0x3c);
    
    setbuf(stdout,NULL);
    setbuf(stdin,NULL);
    setbuf(stderr,NULL);

    char ch;
    DIR *dir_ptr = NULL;
    close(pipefd[1]);
    read(pipefd[0],&ch,1);

    int fork_pid = fork();
    if(fork_pid){
        waitpid(fork_pid,NULL,0);
        _exit(0);
    }

    if((dir_ptr = opendir("./sandbox")) == NULL){
        mkdir("./sandbox",S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
    }

    if(chroot("./sandbox") == -1){
        perror("error.");
    }

    if(chdir("/") == -1){
        perror("error.");
    }

    if(setuid(65534) == -1){
        perror("error.");
    }

    //execv(bin[0],bin);

    printf("Input your message,it will echo back.\n");

    char input[0xc0];
    memset(input,0,0xc0);
    read_num(input);

    printf("Take your message:\n");
    printf(input);

    return 0;
}

int main(){
    //printf("uid:%d ,gid:%d\n",getuid(),getgid());

    //char *mmap_addr = mmap(0,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

    //if(mmap_addr == (void *)-1){
    //    perror("mmap error.");
    //}

    alarm(0x3c);

    pipe(pipefd);

    int child_pid = clone(child_func,container_stack+STACK_SIZE,CLONE_NEWUSER,NULL);

    set_uid_map(child_pid,1000,1000,65534);
    set_gid_map(child_pid,1000,1000,65534);

    close(pipefd[1]);

    if(child_pid != -1){
        waitpid(child_pid,NULL,__WCLONE);
        //if(munmap(mmap_addr,0x10000) == -1){
        //    perror("munmap error.");
        //}
    }

    return 0;
}
