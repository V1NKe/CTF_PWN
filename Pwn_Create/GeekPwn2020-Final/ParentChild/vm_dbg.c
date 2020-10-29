/* lc3.c */
/* Includes */
//gcc -s -z now -fPIC -pie vm.c -o pwn
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <sys/mman.h>


/* Registers */
enum
{
    R_R0 = 0,
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6,
    R_R7,
    R_PC, /* program counter */
    R_COND,
    R_COUNT
};

/* Opcodes */
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

/* Condition Flags */
enum
{
    FL_POS = 1 << 0, /* P */
    FL_ZRO = 1 << 1, /* Z */
    FL_NEG = 1 << 2, /* N */
};

/* Memory Mapped Registers */
enum
{
    MR_KBSR = 0xFE00, /* keyboard status */
    MR_KBDR = 0xFE02  /* keyboard data */
};

/* TRAP Codes */
enum
{
    TRAP_GETC = 0x20,  /* get character from keyboard, not echoed onto the terminal */
    TRAP_OUT = 0x21,   /* output a character */
    TRAP_PUTS = 0x22,  /* output a word string */
    TRAP_IN = 0x23,    /* get character from keyboard, echoed onto the terminal */
    TRAP_PUTSP = 0x24, /* output a byte string */
    TRAP_HALT = 0x25,   /* halt the program */
    TRAP_EXIT = 0x26,   /* halt the program */
};


/* Memory Storage */
/* 65536 locations */
uint16_t *memory;

/* Register Storage */
uint16_t *reg;


/* Functions */
/* Sign Extend */
uint16_t sign_extend(uint16_t x, int bit_count)
{
    if ((x >> (bit_count - 1)) & 1) {
        x |= (0xFFFF << bit_count);
    }
    return x;
}

/* Swap */
uint16_t swap16(uint16_t x)
{
    return (x << 8) | (x >> 8);
}

/* Update Flags */
void update_flags(uint16_t r)
{
    if (reg[r] == 0)
    {
        reg[R_COND] = FL_ZRO;
    }
    else if (reg[r] >> 15) /* a 1 in the left-most bit indicates negative */
    {
        reg[R_COND] = FL_NEG;
    }
    else
    {
        reg[R_COND] = FL_POS;
    }
}


void read_image_input(){
    uint16_t origin;
    printf("Input the code: ");
    fflush(stdout);
    read(0, &origin, sizeof(origin));
    origin = swap16(origin);

    uint16_t max_read = UINT16_MAX - origin;
    uint16_t* p = memory + origin;
    size_t size = read(0, p, max_read);
    while (size-- > 0)
    {
        *p = swap16(*p);
        ++p;
    }
}


/* Check Key */
uint16_t check_key()
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    return select(1, &readfds, NULL, NULL, &timeout) != 0;
}

/* Memory Access */
void mem_write(int64_t address, uint16_t val)
{
    //if (address < 0) {
    //    exit(0);
    //}
    memory[address] = val;
}

uint16_t mem_read(int64_t address)
{
    //if (address < 0) {
    //    printf("%lld",address);
    //}
    if (address == MR_KBSR)
    {
        if (check_key())
        {
            memory[MR_KBSR] = (1 << 15);
            memory[MR_KBDR] = getchar();
        }
        else
        {
            memory[MR_KBSR] = 0;
        }
    }
    return memory[address];
}

/* Input Buffering */
struct termios original_tio;

void disable_input_buffering()
{
    tcgetattr(STDIN_FILENO, &original_tio);
    struct termios new_tio = original_tio;
    new_tio.c_lflag &= ~ICANON & ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
}

void restore_input_buffering()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &original_tio);
}

/* Handle Interrupt */
void handle_interrupt(int signal)
{
    restore_input_buffering();
    printf("\n");
    exit(-2);
}

void print_banner() {
 puts(" ____                      _    ____ _     _ _     _ ");
 puts("|  _ \\ __ _ _ __ ___ _ __ | |_ / ___| |__ (_) | __| |");
 puts("| |_) / _` | '__/ _ \\ '_ \\| __| |   | '_ \\| | |/ _` |");
 puts("|  __/ (_| | | |  __/ | | | |_| |___| | | | | | (_| |");
 puts("|_|   \\__,_|_|  \\___|_| |_|\\__|\\____|_| |_|_|_|\\__,_|");
}

void init() {
    alarm(15);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    print_banner();

    memory = (uint16_t*) malloc(sizeof(uint16_t) * UINT16_MAX);
    reg = (uint16_t*) malloc(sizeof(uint16_t) * R_COUNT);
}

void cleanup() {
    free(memory);
    free(reg);
}

void add(uint16_t instr)
{
	/* destination register (DR) */
	uint16_t r0 = (instr >> 9) & 0x7;
	/* first operand (SR1) */
	uint16_t r1 = (instr >> 6) & 0x7;
	/* whether we are in immediate mode */
	uint16_t imm_flag = (instr >> 5) & 0x1;
                    
	if (imm_flag)
	{
		uint16_t imm5 = sign_extend(instr & 0x1F, 5);
		reg[r0] = reg[r1] + imm5;
	}
	else
	{
		uint16_t r2 = instr & 0x7;
		reg[r0] = reg[r1] + reg[r2];
	}
                    
	update_flags(r0);
}

void and(uint16_t instr)
{
	uint16_t r0 = (instr >> 9) & 0x7;
    uint16_t r1 = (instr >> 6) & 0x7;
    uint16_t imm_flag = (instr >> 5) & 0x1;
                    
    if (imm_flag)
    {
    	uint16_t imm5 = sign_extend(instr & 0x1F, 5);
        reg[r0] = reg[r1] & imm5;
    }
    else
    {
    uint16_t r2 = instr & 0x7;
    reg[r0] = reg[r1] & reg[r2];
    }
    update_flags(r0);
}

void not(uint16_t instr){
						uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t r1 = (instr >> 6) & 0x7;
                    
                        reg[r0] = ~reg[r1];
                        update_flags(r0);
}

void jmp(uint16_t instr)
{
	                    /* Also handles RET */
                        uint16_t r1 = (instr >> 6) & 0x7;
                        reg[R_PC] = reg[r1];
}

void ld(uint16_t instr){
	                    uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t pc_offset = sign_extend(instr & 0x1ff, 9);
                        reg[r0] = mem_read(reg[R_PC] + pc_offset);
                        update_flags(r0);
}

void ldr(uint16_t instr){
	                    uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t r1 = (instr >> 6) & 0x7;
                        uint16_t r2 = (instr >> 3) & 0x7;
                        uint16_t r3 = instr & 0x7;
                        //int32_t addr = (reg[r1] << 16) + reg[r2];
                        int64_t addr = (reg[r0] << 0x30) + (reg[r1] << 0x20) + (reg[r2] << 0x10) + reg[r3];
                        // [BUG] OOB Read!
                        reg[R_R7] = mem_read(addr);
                        update_flags(r0);
}

void lea(uint16_t instr){
	                    uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t pc_offset = sign_extend(instr & 0x1ff, 9);
                        reg[r0] = reg[R_PC] + pc_offset;
                        update_flags(r0);
}

void st(uint16_t instr){
	                    uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t pc_offset = sign_extend(instr & 0x1ff, 9);
                        mem_write(reg[R_PC] + pc_offset, reg[r0]);
}

void str(uint16_t instr){
	                    uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t r1 = (instr >> 6) & 0x7;
                        uint16_t r2 = (instr >> 3) & 0x7;
                        uint16_t r3 = instr & 0x7;
                        uint16_t offset = sign_extend(instr & 0x3F, 6);
                        //int32_t addr = (reg[r1] << 16) + reg[r2];
                        int64_t addr = (reg[r0] << 0x30) + (reg[r1] << 0x20) + (reg[r2] << 0x10) + reg[r3];
                        // [BUG] OOB Write!
                        mem_write(addr, reg[R_R7]);
}

/* Main Loop */

int main(int argc, const char* argv[])
{
    /* Setup */
    init();
    signal(SIGINT, handle_interrupt);
    disable_input_buffering();
    int has_next = 1;


    while (has_next) {
        read_image_input();
        /* set the PC to starting position */
        /* 0x3000 is the default */
        enum { PC_START = 0x3000 };
        reg[R_PC] = PC_START;
        int running = 1;

        while (running)
        {
            /* FETCH */
            uint16_t instr = mem_read(reg[R_PC]++);
            uint16_t op = instr >> 12;

            switch (op)
            {
                case OP_ADD:
                    /* ADD */
                    {
                	//__asm__("int $0x03");
                    	add(instr);                		
                    }

                    break;
                case OP_AND:
                    /* AND */
                    {
                        //__asm__("int $0x03");
                    	and(instr);   
                    }

                    break;
                case OP_NOT:
                    /* NOT */
                    {
                        //__asm__("int $0x03");
                    	not(instr); 
                    }

                    break;
                case OP_BR:
                    /* BR */
                    {
                    	uint16_t pc_offset = sign_extend((instr) & 0x1ff, 9);
                        uint16_t cond_flag = (instr >> 9) & 0x7;
                        if (cond_flag & reg[R_COND])
                        {
                            reg[R_PC] += pc_offset;
                        }
                    }

                    break;
                case OP_JMP:
                    /* JMP */
                    {
                    	//__asm__("int $0x03");
                    	jmp(instr); 
                    }

                    break;
                case OP_JSR:
                    /* JSR */
                    {
                    	uint16_t r1 = (instr >> 6) & 0x7;
                        uint16_t long_pc_offset = sign_extend(instr & 0x7ff, 11);
                        uint16_t long_flag = (instr >> 11) & 1;
                    
                        reg[R_R7] = reg[R_PC];
                        if (long_flag)
                        {
                            reg[R_PC] += long_pc_offset;  /* JSR */
                        }
                        else
                        {
                            reg[R_PC] = reg[r1]; /* JSRR */
                        }
                        break;
                    }

                    break;
                case OP_LD:
                    /* LD */
                    {
                    	//__asm__("int $0x03");
                    	ld(instr);
                    }

                    break;
                case OP_LDI:
                    /* LDI */
                    {
                    	/* destination register (DR) */
                        uint16_t r0 = (instr >> 9) & 0x7;
                        /* PCoffset 9*/
                        uint16_t pc_offset = sign_extend(instr & 0x1ff, 9);
                        /* add pc_offset to the current PC, look at that memory location to get the final address */
                        reg[r0] = mem_read(mem_read(reg[R_PC] + pc_offset));
                        update_flags(r0);
                    }

                    break;
                case OP_LDR:
                    /* LDR */
                    {
                    	//__asm__("int $0x03");
                    	ldr(instr);
                    }

                    break;
                case OP_LEA:
                    /* LEA */
                    {
                    	//__asm__("int $0x03");
                    	lea(instr);
                    }

                    break;
                case OP_ST:
                    /* ST */
                    {
    			//__asm__("int $0x03");
                    	st(instr);
                    }

                    break;
                case OP_STI:
                    /* STI */
                    {
    					uint16_t r0 = (instr >> 9) & 0x7;
                        uint16_t pc_offset = sign_extend(instr & 0x1ff, 9);
                        mem_write(mem_read(reg[R_PC] + pc_offset), reg[r0]);
                    }

                    break;
                case OP_STR:
                    /* STR */
                    {
                    	//__asm__("int $0x03");
                    	str(instr);
                    }

                    break;
                case OP_TRAP:
                    /* TRAP */
    				{
                    	switch (instr & 0xFF)
                    		{
                        case TRAP_GETC:
                            /* TRAP GETC */
                            /* read a single ASCII char */
                            reg[R_R0] = (uint16_t)getchar();

                            break;
                        case TRAP_OUT:
                            /* TRAP OUT */
                            putc((char)reg[R_R7], stdout);
                            putc((char)(reg[R_R7]>>8), stdout);
                            fflush(stdout);

                            break;
                        case TRAP_PUTS:
                            /* TRAP PUTS */
                            {
                                /* one char per word */
                                uint16_t* c = memory + reg[R_R0];
                                while (*c)
                                {
                                    putc((char)*c, stdout);
                                    ++c;
                                }
                                fflush(stdout);
                            }

                            break;
                        case TRAP_IN:
                            printf("c:");
                            char c = getchar();
                            putc(c, stdout);
                            reg[R_R7] = (uint16_t)c;

                            break;
                        case TRAP_PUTSP:
                            /* TRAP PUTSP */
                            {
                                /* one char per byte (two bytes per word)
                                here we need to swap back to
                                big endian format */
                                uint16_t* c = memory + reg[R_R0];
                                while (*c)
                                {
                                    char char1 = (*c) & 0xFF;
                                    putc(char1, stdout);
                                    char char2 = (*c) >> 8;
                                    if (char2) putc(char2, stdout);
                                    ++c;
                                }
                                fflush(stdout);
                            }

                            break;
                        case TRAP_HALT:
                            /* TRAP HALT */
                            puts("STOP");
                            fflush(stdout);
                            running = 0;
                            break;

                        case TRAP_EXIT:
                            fflush(stdout);
                            cleanup();
                            exit(0);

                    	}
                    }

                    break;
                case OP_RES:
                case OP_RTI:
                default:
                    /* BAD OPCODE */
                    abort();
                    break;
            }
        }
    }
    /* Shutdown */
    restore_input_buffering();
}


