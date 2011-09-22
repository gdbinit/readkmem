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
 * v0.2 - Some fixes
 * v0.3 - More improvements, more useful now!
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
#include <getopt.h>
#include <ctype.h>

#define DEBUG 1
#define VERSION "0.3"

#define x86 0
#define x64	1

#define MAX_SIZE 500000

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

void readkmem(void *m,off_t off,uint64_t size)
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

void writekmem(void *m,off_t off,uint64_t size)
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
	fprintf(stderr,"readkmem -a address -s size [-out filename]\n");
	fprintf(stderr,"Available Options : \n");
	fprintf(stderr,"       -out filename	file to write binary output to\n");
	exit(1);
}

void header(void)
{
	fprintf(stderr,"Readkmem v%s - (c) fG!\n",VERSION);
	fprintf(stderr,"-----------------------\n");
}

int main(int argc, char ** argv)
{
    
	// required structure for long options
	static struct option long_options[]={
		{ "address", required_argument, NULL, 'a' },
		{ "size", required_argument, NULL, 's' },
		{ "out", required_argument, NULL, 'o' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0, c;
	char *outputname=NULL;
	
	uint64_t address=0, size=0;
	
	// process command line options
	while ((c = getopt_long (argc, argv, "a:s:o:", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case ':':
				usage();
				exit(1);
				break;
			case '?':
				usage();
				exit(1);
				break;
			case 'o':
				outputname = optarg;
				break;
			case 'a':
				address = strtoul(optarg, NULL, 0);
				break;
			case 's':
				size = strtoul(optarg, NULL, 0);
				break;
			default:
				usage();
				exit(1);
		}
	}
	
	header();

	if (argc < 3)
	{
		usage();
	}
	
	// we need to run this as root
	if (getuid() != 0)
	{
		printf("[ERROR] Please run me as root!\n");
		exit(1);
	}
	
	kernel_type = get_kernel_type();
	if (kernel_type == -1)
	{
		printf("[ERROR] Unable to retrieve kernel type!\n");
		exit(1);
	}
	
	if(!(fd_kmem=open("/dev/kmem",O_RDWR)))
	{
		fprintf(stderr,"[ERROR] Error while opening /dev/kmem. Is /dev/kmem enabled?\n");
		fprintf(stderr,"Add parameter kmem=1 to /Library/Preferences/SystemConfiguration/com.apple.Boot.plist\n");
		exit(1);
	}
	
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
	
	FILE *outputfile;
	if (outputname != NULL)
	{
		
		if ( (outputfile = fopen(outputname, "wb")) == NULL)
		{
			fprintf(stderr,"[ERROR] Cannot open %s for output!\n", outputname);
			exit(1);
		}
	}
	
	// read kernel memory
    readkmem(read, address, size);
	
	if (outputname != NULL)
	{
		if (fwrite(read, size, 1, outputfile) < 1)
		{
			fprintf(stderr,"[ERROR] Write error at %s occurred!\n", outputname);
			exit(1);
		}
		printf("\n[OK] Memory dumped to %s!\n\n", outputname);
	}
	else
	{
		int i=0,x,z;
		printf("Memory hex dump @ %p:\n\n", (void*)address);
		// 16 columns
		while (i<size)
		{
			printf("%08lx ",address);
			z = i;
			for (x = 0; x < 16; x++)
			{
				printf("%02x ", read[z++]);
			}
			z = i;
			for (x = 0; x < 16; x++)
			{
				printf("%c", isascii(read[z]) && isprint(read[z]) ? read[z] : '.');
				z++;
			}
			i+=16;
			printf("\n");
			address += 16;
		}
		printf("\n");		
	}

    free(read);
	return 0;
}
