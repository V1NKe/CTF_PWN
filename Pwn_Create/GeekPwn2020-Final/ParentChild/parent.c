//gcc -s -z now -fstack-protector-all parent.c -o parent
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>

enum
{
    OP_BR = 0, /* branch */
    OP_ADD,    /* add  */
    OP_LD,     /* load */
    OP_ST,     /* store */
    OP_JSR,    /* jump register */
    OP_AND,    /* bitwise and */
    OP_LDR,    /* load register */
    OP_STR,    /* store register */
    OP_RTI,    /* unused */
    OP_NOT,    /* bitwise not */
    OP_LDI,    /* load indirect */
    OP_STI,    /* store indirect */
    OP_JMP,    /* jump */
    OP_RES,    /* reserved (unused) */
    OP_LEA,    /* load effective address */
    OP_TRAP    /* execute trap */
};

struct user_regs_struct regs;

void child_process(char *argv){
	if(ptrace(PTRACE_TRACEME,0,0,0) != -1){
		execlp(argv,argv,NULL);
		exit(0);
	}
	fprintf(stderr, "ERROR %s\n", "PTRACE_TRACEME");
}

void parent_process(pid_t pid){
    int status;
    waitpid(pid,&status,0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, 1);
    ptrace(PTRACE_CONT, pid, 0, 0);
    //ptrace(PTRACE_SYSCALL,pid,0,0);
    while(1){//(status & 0xFF) == 0x7F
    	//ptrace(PTRACE_SYSCALL,pid,0,0);
    	waitpid(pid,&status,0);
    	ptrace(PTRACE_GETREGS, pid, 0LL, &regs);
    	uint8_t check_CC = ptrace(PTRACE_PEEKDATA,pid,regs.rip - 1,0) & 0xFF;
    	if(check_CC == 0xCC){
    		uint16_t opcode = ptrace(PTRACE_PEEKDATA,pid,(void *)(regs.rsp+0x24),0) & 0xFFFF;
    		uint16_t intstr = ptrace(PTRACE_PEEKDATA,pid,(void *)(regs.rsp+0x22),0) & 0xFFFF;
    		regs.rdi = intstr;
    		regs.rsp -= 8;
    		uint64_t pc_str = regs.rip;
    		uint64_t offset;
    		switch(opcode){
    			case OP_ADD:
    				{
    					offset = 0x184A - 0x116e;
    				}

    				break;
    			case OP_AND:
    				{
    					offset = 0x1850 - 0x125D;
    					//regs.rip = pc_str - offset;
    					//ptrace(PTRACE_POKEDATA,pid,(void *)regs.rsp,pc_str);
    				}

    				break;
    			case OP_NOT:
    				{
    					offset = 0x1856 - 0x134A;
    				}

    				break;
    			case OP_JMP:
    				{
    					offset = 0x18CF - 0x13B4;
    				}

    				break;
    			case OP_LD:
    				{
    					offset = 0x198C - 0x13F8;
    				}

    				break;
    			case OP_LDR:
    				{
    					offset = 0x1A11 - 0x147E;
    				}

    				break;
    			case OP_LEA:
    				{
    					offset = 0x1A17 - 0x1581;
    				}

    				break;
    			case OP_ST:
    				{
    					offset = 0x1A1D - 0x15F3;
    				}

    				break;
    			case OP_STR:
    				{
    					offset = 0x1A9B - 0x166C;
    				}

    				break;
    		}
    		regs.rip = pc_str - offset;
    		ptrace(PTRACE_POKEDATA,pid,(void *)regs.rsp,pc_str);
    		ptrace(PTRACE_SETREGS,pid,0,&regs);
    	}
    	else if ((status & 0xFF) == 0x7F){ 
    		if (regs.orig_rax != 0 && regs.orig_rax != 1 && regs.orig_rax != 2 && regs.orig_rax != 10){
    			//printf("1\n");
    			//printf("%lld\n", regs.orig_rax);
    			//printf("0x%lx\n", ptrace(PTRACE_PEEKDATA,pid,(void *)regs.rdi,0));
    			//printf("0x%lx\n", ptrace(PTRACE_PEEKDATA,pid,regs.rdi+8,0));
    			ptrace(PTRACE_KILL,pid,0,0);
    			exit(0);
    		}
    	}
    	else{
    		//printf("2\n");
    		ptrace(PTRACE_KILL,pid,0,0);
    		exit(0);
    	}
    	ptrace(PTRACE_SYSCALL,pid,0,0);
    }
}

void fork_pid(char *argv){
	pid_t pid;
	pid = fork();
	if(!pid){
		child_process(argv);
	}
	if(pid == -1){
		fprintf(stderr, "ERROR %s\n", "FORK");
	}
	parent_process(pid);
}

int main (int argc,char *argv[]){
	if(argc > 1){
		setvbuf(stdout, 0, 2, 0);
    	setvbuf(stdin, 0, 2, 0);
		fork_pid(argv[1]);
		return 0;
	}
	else{
		fprintf(stderr, "%s <args>\n", *argv);
		return 1;
	}
}
