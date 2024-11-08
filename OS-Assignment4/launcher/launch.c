//Because loader is not present in same directory so we need to get it from another sub-directory:
#include "../loader/loader.h"

int fd1;
Elf32_Ehdr *ehdr;
int elf_check_file(Elf32_Ehdr *hdr) {
  if(!hdr) return 0;
  if(hdr->e_ident[EI_MAG0] != ELFMAG0) {
    return 0;
  }
  if(hdr->e_ident[EI_MAG1] != ELFMAG1) {
    return 0;
  }
  if(hdr->e_ident[EI_MAG2] != ELFMAG2) {
    return 0;
  }
  if(hdr->e_ident[EI_MAG3] != ELFMAG3) {
    return 0;
  }
  return 1;
}
void loader_cleanup() {
  if(ehdr){
    free(ehdr);
    ehdr=NULL;
  }
  close(fd1);
}
int main(int argc, char** argv) 
{
  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \n",argv[0]);
    exit(1);
  }
  fd1 = open(argv[1], O_RDONLY);
  //1.Load entire binary content into the memory from the ELF file.
  //2.checking error in opening executable file:
  if(fd1<0){
   printf("Error in opening the executable file");
   loader_cleanup();
   exit(1);
  }
  //3.Allocating size to elf header:
  int size1=sizeof(Elf32_Ehdr);
  ehdr=(Elf32_Ehdr *)malloc(size1);
  //4.Checking error that allocation of space has been done properly or not:
  if(ehdr==NULL){
    printf("Space Allocation not done for elf header");
    loader_cleanup();
    exit(1);
  }
  //5.reading Elf header to get offset of Phdr as well as e_entry:
  int read1=read(fd1,ehdr,size1);
  //6.checking wheather reading is done properly or not:
  if(read1!=size1){
    printf("Cannnot read properly elf header");
    loader_cleanup();
    exit(1);
  }
  if(!elf_check_file(ehdr)){
    printf("Not an executable file:");
    exit(1);
  }

  close(fd1);
  // 1. carry out necessary checks on the input ELF file
  // 2. passing it to the loader for carrying out the loading/execution
  load_and_run_elf(argv);
  // 3. invoke the cleanup routine inside the loader  
  loader_cleanup();
  return 0;
}
