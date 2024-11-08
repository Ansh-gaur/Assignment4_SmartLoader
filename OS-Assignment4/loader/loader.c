#include "loader.h"
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

Elf32_Ehdr *ehdr; // Pointer to ELF header
Elf32_Phdr *phdr; // Pointer to Program headers
int fd; // File descriptor
int page_faults = 0; // Counter for page faults
int pages_allocated = 0; // Counter for allocated pages

#define PAGE_SIZE 4096 // Page size of 4KB

int internal_fragmentation=0;
/*
 * Release memory and other cleanups
 */
void loader_cleanup() {
    if(ehdr) {
        free(ehdr);
        ehdr = NULL;
    }
    if(phdr) {
        free(phdr);
        phdr = NULL;
    }
    close(fd);
}

/*
 * Signal handler for segmentation faults
 */
void page_fault_handler(int sig, siginfo_t *si, void *unused) {
    void *fault_addr = si->si_addr;
    page_faults++; // Increment page fault count

    // Find the segment corresponding to the fault address
    for(int i = 0; i < ehdr->e_phnum; i++) {
        if((char *)fault_addr >= (char *)phdr[i].p_vaddr &&
           (char *)fault_addr < (char *)(phdr[i].p_vaddr + phdr[i].p_memsz)) {

            // Calculate the page-aligned address to mmap
            void *page_start = (void *)((uintptr_t)fault_addr & ~(PAGE_SIZE - 1));
            pages_allocated++; // Increment page allocation count

            // Allocate one page with mmap for the faulting segment
            void *mapped_mem = mmap(page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if(mapped_mem == MAP_FAILED) {
                perror("mmap failed");
                exit(1);
            }

            // Move file descriptor to segment offset
           // Calculate the offset for the read operation
           int offset = phdr[i].p_offset + ((uintptr_t)page_start - phdr[i].p_vaddr);
           if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
               perror("lseek failed");
               exit(1);
            }
            void *end=(char *)(phdr[i].p_vaddr + phdr[i].p_memsz);
            if (end - fault_addr < PAGE_SIZE) internal_fragmentation += PAGE_SIZE - (end - fault_addr);

            // Calculate how many bytes to read
           int offset_within_segment = (uintptr_t)page_start - phdr[i].p_vaddr;
           int remaining_size = phdr[i].p_filesz - offset_within_segment; // Remaining bytes in segment
           int to_read = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

           // Read from the file into the mapped memory
           ssize_t bytes_read = read(fd, mapped_mem, to_read);
              if (bytes_read < 0) {
                 perror("Segment load failed (read error)");
                  exit(1);
              } else if (bytes_read < to_read) {
                   fprintf(stderr, "Segment load failed: Expected to read %d bytes but read %ld bytes.\n",
                  to_read, (long)bytes_read);
                  exit(1); 
              }
              return;

        }
    }

    // If no segment matched the faulting address, terminate
    //printf("Segmentation fault at address %p\n", fault_addr);
    loader_cleanup();
    exit(1);
}

/*
 * Load and run the ELF executable file
 */
void load_and_run_elf(char **exe) {
    // Register the custom signal handler for segmentation faults
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = page_fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    fd = open(exe[1], O_RDONLY);
    if(fd < 0) {
        perror("Error opening executable file");
        loader_cleanup();
        exit(1);
    }

    // Allocate space for the ELF header and read it
    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    if(!ehdr || read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        perror("Error reading ELF header");
        loader_cleanup();
        exit(1);
    }

    // Allocate space for program headers and read them
    int phdr_size = ehdr->e_phnum * ehdr->e_phentsize;
    phdr = (Elf32_Phdr *)malloc(phdr_size);
    lseek(fd, ehdr->e_phoff, SEEK_SET);
    if(!phdr || read(fd, phdr, phdr_size) != phdr_size) {
        perror("Error reading program headers");
        loader_cleanup();
        exit(1);
    }

    // Directly attempt to run _start (entry point) without pre-allocating memory for segments
    int (*_start)(void) = (int (*)(void))(ehdr->e_entry);
    int result = _start();

    printf("User _start return value = %d\n", result);
    loader_cleanup();

    // Report page fault stats
    printf("Total page faults: %d\n", page_faults);
    printf("Total pages allocated: %d\n", pages_allocated);
    printf("Internal fragmentation (in KB): %d\n", (internal_fragmentation) / 1024);
}