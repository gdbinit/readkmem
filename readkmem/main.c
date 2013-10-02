/*
 *     _____                                _____
 *  __|__   |__  ______  ____    _____   __| __  |__  ____    __  ______  ____    __
 * |     |     ||   ___||    \  |     \ |  |/ /     ||    \  /  ||   ___||    \  /  |
 * |     \     ||   ___||     \ |      \|     \     ||     \/   ||   ___||     \/   |
 * |__|\__\  __||______||__|\__\|______/|__|\__\  __||__/\__/|__||______||__/\__/|__|
 *    |_____|                              |_____|
 *
 * Readkmem
 *
 * A small util to dump kernel memory and kernel binaries
 *
 * Copyright (c) fG! - 2012,2013. All rights reserved.
 * reverser@put.as - http://reverse.put.as
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
 * v0.4 - Code cleanups
 * v0.5 - Add feature to dump mach-o binaries from kernel space
 *        Code cleanups
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include <mach-o/loader.h>
#include <stddef.h>
#include <assert.h>

#define VERSION "0.5"

#define x86 0
#define x64	1

mach_vm_address_t vmaddr_slide = 0;

void header(void);
int8_t get_kernel_type (void);
void readkmem(uint32_t fd, void *buffer, off_t off, size_t size);
void usage(void);
static size_t get_image_size(uint32_t fd, off_t address);
static void dump_binary(uint32_t fd, off_t address, void *buffer);

/*
 * we need to find the binary file size
 * which is taken from the filesize field of each segment command
 * and not the vmsize (because of alignment)
 * if we dump using vmaddresses, we will get the alignment space into the dumped
 * binary and get into problems :-)
 */
static size_t
get_image_size(uint32_t fd, off_t address)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // allocate a buffer to read the header info
    // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
    // but this will work for this purpose so no need for more complexity!
    struct mach_header header;
    readkmem(fd, &header, address, sizeof(struct mach_header));
    
    if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
    {
		printf("[ERROR] Target is not a mach-o binary!\n");
        exit(1);
    }
    
    size_t imagefilesize = 0;
    
    // read the load commands
    uint8_t *loadcmds = malloc(header.sizeofcmds*sizeof(uint8_t));
    uint16_t mach_header_size = 0;
    if (header.magic == MH_MAGIC)
        mach_header_size = sizeof(struct mach_header);
    else if (header.magic == MH_MAGIC_64)
        mach_header_size = sizeof(struct mach_header_64);
    
    readkmem(fd, loadcmds, address+mach_header_size, header.sizeofcmds);
    
    // process and retrieve address and size of linkedit
    uint8_t *loadCmdAddress = 0;
    // first load cmd address
    loadCmdAddress = (uint8_t*)loadcmds;
    struct load_command *loadCommand    = NULL;
    struct segment_command *segCmd      = NULL;
    struct segment_command_64 *segCmd64 = NULL;
    // process commands to find the info we need
    for (uint32_t i = 0; i < header.ncmds; i++)
    {
        loadCommand = (struct load_command*)loadCmdAddress;
        // 32bits and 64 bits segment commands
        // LC_LOAD_DYLIB to find the ordinal
        if (loadCommand->cmd == LC_SEGMENT)
        {
            segCmd = (struct segment_command*)loadCmdAddress;
            if (strcmp((char*)(segCmd->segname), "__PAGEZERO") != 0)
            {
                if (strcmp((char*)(segCmd->segname), "__TEXT") == 0)
                {
                    vmaddr_slide = address - segCmd->vmaddr;
                }
                imagefilesize += segCmd->filesize;
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segCmd64 = (struct segment_command_64*)loadCmdAddress;
            if (strcmp((char*)(segCmd64->segname), "__PAGEZERO") != 0)
            {
                if (strcmp((char*)(segCmd64->segname), "__TEXT") == 0)
                {
                    vmaddr_slide = address - segCmd64->vmaddr;
                }
                imagefilesize += segCmd64->filesize;
            }
        }
        // advance to next command
        loadCmdAddress += loadCommand->cmdsize;
    }
end:
    free(loadcmds);
    return imagefilesize;
}


/*
 * dump the binary into the allocated buffer
 * we dump each segment and advance the buffer
 */
static void
dump_binary(uint32_t fd, off_t address, void *buffer)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // allocate a buffer to read the header info
    // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
    // but this will work for this purpose so no need for more complexity!
    struct mach_header header;
    readkmem(fd, &header, address, sizeof(struct mach_header));
    
    if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
    {
		printf("[ERROR] Target is not a mach-o binary!\n");
        exit(1);
    }
    
    // read the header info to find the LINKEDIT
    uint8_t *loadcmds = malloc(header.sizeofcmds*sizeof(uint8_t));
    
    uint16_t mach_header_size = 0;
    if (header.magic == MH_MAGIC)
        mach_header_size = sizeof(struct mach_header);
    else if (header.magic == MH_MAGIC_64)
        mach_header_size = sizeof(struct mach_header_64);
    // retrieve the load commands
    readkmem(fd, loadcmds, address+mach_header_size, header.sizeofcmds);
    
    // process and retrieve address and size of linkedit
    uint8_t *loadCmdAddress = 0;
    // first load cmd address
    loadCmdAddress = (uint8_t*)loadcmds;
    struct load_command *loadCommand    = NULL;
    struct segment_command *segCmd      = NULL;
    struct segment_command_64 *segCmd64 = NULL;
    // process commands to find the info we need
    for (uint32_t i = 0; i < header.ncmds; i++)
    {
        loadCommand = (struct load_command*)loadCmdAddress;
        // 32bits and 64 bits segment commands
        // LC_LOAD_DYLIB to find the ordinal
        if (loadCommand->cmd == LC_SEGMENT)
        {
            segCmd = (struct segment_command*)loadCmdAddress;
            if (strcmp((char*)(segCmd->segname), "__PAGEZERO") != 0)
            {
#if DEBUG
                printf("[DEBUG] Dumping %s at 0x%llx with size 0x%x (buffer:%x)\n", segCmd->segname, segCmd->vmaddr+vmaddr_slide, segCmd->filesize, (uint32_t)buffer);
#endif
                // sync buffer position with file offset
                buffer += segCmd->fileoff;
                // we don't need to dump header plus load cmds because __TEXT segment address includes them!
                readkmem(fd, buffer, segCmd->vmaddr+vmaddr_slide, segCmd->filesize);
            }
            
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segCmd64 = (struct segment_command_64*)loadCmdAddress;
            if (strcmp((char*)(segCmd64->segname), "__PAGEZERO") != 0)
            {
#if DEBUG
                printf("[DEBUG] Dumping %s at 0x%llx with size 0x%llx (buffer:%p)\n", segCmd64->segname, segCmd64->vmaddr+vmaddr_slide, segCmd64->filesize, buffer);
#endif
                // sync buffer position with file offset
                buffer += segCmd64->fileoff;
                // we don't need to dump header plus load cmds because __TEXT segment address includes them!
                readkmem(fd, buffer, segCmd64->vmaddr+vmaddr_slide, segCmd64->filesize);
            }
        }
        // advance to next command
        loadCmdAddress += loadCommand->cmdsize;
    }
end:
    free(loadcmds);
}

// retrieve which kernel type are we running, 32 or 64 bits
int8_t
get_kernel_type (void)
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

void
readkmem(uint32_t fd, void *buffer, off_t off, size_t size)
{
	if(lseek(fd, off, SEEK_SET) != off)
	{
		fprintf(stderr,"[ERROR] Error in lseek. Are you root? \n");
		exit(-1);
	}
    ssize_t bytes_read = read(fd, buffer, size);
	if(bytes_read != size)
	{
        fprintf(stderr,"[ERROR] Error while trying to read from kmem. Asked %ld bytes from offset %llx, returned %ld.\n", size, off, bytes_read);
	}
}

void
usage(void)
{
	fprintf(stderr,"readkmem -a address -s size [-o filename] [-f]\n");
	fprintf(stderr,"Available Options : \n");
	fprintf(stderr," -o filename  file to write binary output to\n");
    fprintf(stderr," -f           make a full dump of target binary\n");
	exit(1);
}

void
header(void)
{
    
    fprintf(stderr," _____           _ _____\n");
    fprintf(stderr,"| __  |___ ___ _| |  |  |_____ ___ _____\n");
    fprintf(stderr,"|    -| -_| .'| . |    -|     | -_|     |\n");
    fprintf(stderr,"|__|__|___|__,|___|__|__|_|_|_|___|_|_|_|\n");
	fprintf(stderr,"         Readkmem v%s - (c) fG!\n",VERSION);
	fprintf(stderr,"-----------------------------------------\n");
}

int main(int argc, char ** argv)
{
    
	// required structure for long options
	static struct option long_options[]={
		{ "address", required_argument, NULL, 'a' },
		{ "size", required_argument, NULL, 's' },
		{ "out", required_argument, NULL, 'o' },
        { "full", no_argument, NULL, 'f' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0;
    int c = 0;
	char *outputname = NULL;
	
	uint64_t address = 0;
    size_t size = 0;
    uint8_t  fulldump = 0;
	
	// process command line options
	while ((c = getopt_long (argc, argv, "a:s:o:f", long_options, &option_index)) != -1)
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
            case 'f':
                fulldump = 1;
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
	
	int8_t kernel_type = get_kernel_type();
	if (kernel_type == -1)
	{
		printf("[ERROR] Unable to retrieve kernel type!\n");
		exit(1);
	}
	
    int32_t fd_kmem;
    
	if((fd_kmem = open("/dev/kmem",O_RDWR)) == -1)
	{
		fprintf(stderr,"[ERROR] Error while opening /dev/kmem. Is /dev/kmem enabled?\n");
		fprintf(stderr,"Add parameter kmem=1 to /Library/Preferences/SystemConfiguration/com.apple.Boot.plist\n");
		exit(1);
	}
	    
    uint8_t *read_buffer = NULL;
    
	FILE *outputfile;	
	if (outputname != NULL)
	{
		if ( (outputfile = fopen(outputname, "wb")) == NULL)
		{
			fprintf(stderr,"[ERROR] Cannot open %s for output!\n", outputname);
			exit(1);
		}
	}
	
    if (fulldump)
    {
        // first we need to find the file size because memory alignment slack spaces
        size_t imagesize = 0;
        imagesize = get_image_size(fd_kmem, address);
#if DEBUG
        printf("[DEBUG] Target image size is 0x%lx\n", imagesize);
#endif
        read_buffer = calloc(1, imagesize);
        // and finally read the sections and dump their contents to the buffer
        dump_binary(fd_kmem, address, (void*)read_buffer);
        // dump buffer contents to file
        if (outputname != NULL)
        {
            if (fwrite(read_buffer, (long)imagesize, 1, outputfile) < 1)
            {
                fprintf(stderr,"[ERROR] Write error at %s occurred!\n", outputname);
                exit(1);
            }
            printf("\n[OK] Full binary dumped to %s!\n\n", outputname);
        }
    }
    else
    {
        read_buffer = calloc(1, size);
        if (read_buffer == NULL)
        {
            printf("[ERROR] Memory allocation failed!\n");
            exit(1);
        }
        // read kernel memory
        readkmem(fd_kmem, read_buffer, address, size);
        // dump to file
        if (outputname != NULL)
        {
            if (fwrite(read_buffer, size, 1, outputfile) < 1)
            {
                fprintf(stderr,"[ERROR] Write error at %s occurred!\n", outputname);
                exit(1);
            }
            printf("\n[OK] Memory dumped to %s!\n\n", outputname);
        }
        // dump to stdout
        else
        {
            int i = 0;
            int x = 0;
            int z = 0;
            size_t linelength = 0;
            printf("Memory hex dump @ %p:\n\n", (void*)address);
            // 16 columns
            while (i < size)
            {
                linelength = (size - i) <= 16 ? (size - i) : 16;
                printf("%p ",(void*)address);
                z = i;
                for (x = 0; x < linelength; x++, z++)
                {
                    printf("%02x ", read_buffer[z]);
                }
                // make it always 16 columns, this could be prettier :P
                for (x = (int)linelength; x < 16; x++)
                {
                    fprintf(stdout, "   ");
                }
                z = i;
                printf("|");
                for (x = 0; x < linelength; x++, z++)
                {
                    printf("%c", isascii(read_buffer[z]) && isprint(read_buffer[z]) ? read_buffer[z] : '.');
                }
                i += 16;
                printf("|\n");
                address += 16;
            }
            printf("\n");		
        }
    }
    
end:
    free(read_buffer);
	return 0;
}
