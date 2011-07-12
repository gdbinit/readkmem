/*
 * Readkmem
 *
 * fG! - 2011 - reverser@put.as - http://reverse.put.as
 *
 * Note: This requires kmem/mem devices to be enabled
 * Edit /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
 * add kmem=1 parameter, and reboot!
 *
 * To compile:
 * gcc -Wall -o readkmem readkmem.c
 *
 * v0.1 - Initial version
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>

#define DEBUG 1
#define VERSION "0.1"

#define x86 0
#define x64	1

#define MAX_SIZE 5000

/***********GLOBAL**************/
int fd_kmem;
unsigned long ptr_idt;
uint16_t size_idt;
int8_t kernel_type;
/******************************/

void header(void);

// retrieve which kernel type are we running, 32 or 64 bits
int8_t get_kernel_type (void)
{
	size_t size;
	sysctlbyname("hw.machine", NULL, &size, NULL, 0);
	char *machine = malloc(size);
	sysctlbyname("hw.machine", machine, &size, NULL, 0);
	if (strcmp(machine, "i386") == 0)
		return x86;
	else if (strcmp(machine, "x86_64") == 0)
		return x64;
	else
		return -1;
}

void readkmem(void *m,off_t off,int size)
{
	if(lseek(fd_kmem,off,SEEK_SET) != off)
	{
		fprintf(stderr,"[ERROR] Error in lseek. Are you root? \n");
		exit(-1);
	}
	if(read(fd_kmem,m,size) != size)
	{
		fprintf(stderr,"[ERROR] Error while trying to read from kmem\n");
		exit(-1);
	}
}

void writekmem(void *m,off_t off,int size)
{
	if(lseek(fd_kmem,off,SEEK_SET) != off)
	{
		fprintf(stderr,"[ERROR] Error in lseek. Are you root? \n");
		exit(-1);
	}
	if(write(fd_kmem,m,size) != size)
	{
		fprintf(stderr,"[ERROR] Error while trying to write to kmem\n");
		exit(-1);
	}
}

void usage(void)
{
	fprintf(stderr,"Available Options : \n");
	fprintf(stderr,"       -a nb    show all info about one interrupt\n");
	exit(1);
}

void header(void)
{
	fprintf(stderr,"Readkmem v%s - (c) fG!\n",VERSION);
	fprintf(stderr,"-----------------------\n");
}

int main(int argc, char ** argv)
{
    
	header();
	if (argc < 3)
	{
		usage();
	}
	
	kernel_type = get_kernel_type();
	if (kernel_type == -1)
	{
		printf("[ERROR] Unable to retrieve kernel type!\n");
		exit(-1);
	}
	
	if(!(fd_kmem=open("/dev/kmem",O_RDWR)))
	{
		fprintf(stderr,"[ERROR] Error while opening /dev/kmem. Is /dev/kmem enabled?\n");
		exit(-1);
	}
	
    unsigned int address, size;
    size = atoi(argv[2]);
    if (size > MAX_SIZE)
    {
        printf("[ERROR] Invalid size (higher than maximum!)\n");
        exit(1);
    }
    unsigned char *read = malloc(size);
    if (read == NULL)
    {
        printf("[ERROR] Memory allocation failed!\n");
        exit(1);
    }
    sscanf(argv[1],"%x",&address);

    readkmem(read, address, size);

    int i;
    printf("Memory output @ 0x%x:\n", address);
    for (i = 0; i < size; i++)
        printf("%02x ", read[i]);
    printf("\n");
    free(read);
	return 0;
}
