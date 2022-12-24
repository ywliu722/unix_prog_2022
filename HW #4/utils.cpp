#include "utils.hpp"

using namespace std;

// utilities
vector<string> str_split(string &s, char delimeter){
    vector<string> result;
    stringstream ss (s);
    string item;

    while (getline (ss, item, delimeter)){
        if(item == ""){
            continue;
        }
        result.push_back(item);
    }

    return result;
}

string str_toupper(string &s){
    string result = "";
    for(auto c:s){
        
        result += toupper(c);
    }
    return result;
}

// parsing ELF file and get the entry point and .text address, size
elf_info elf_parsing(string &filename){
    elf_info result;
    int fd = open(filename.c_str(), O_RDONLY);
    if(fd<0){
        return result;
    }

    // map ELF file into memory for easier manipulation
    struct stat statbuf;
    fstat(fd, &statbuf);
    char *fbase = (char *)mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);

    // if the file is in ELF64 format
    if(fbase[4] == 2){
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)fbase;
        Elf64_Shdr *sects = (Elf64_Shdr *)(fbase + ehdr->e_shoff);
        int shsize = ehdr->e_shentsize;
        int shnum = ehdr->e_shnum;
        int shstrndx = ehdr->e_shstrndx;

        // put entry point into object
        result.entry_point = ehdr->e_entry;

        /* get string table index */
        Elf64_Shdr *shstrsect = &sects[shstrndx];
        char *shstrtab = fbase + shstrsect->sh_offset;

        int i;
        for(i=0; i<shnum; i++) {
            if(!strcmp(shstrtab+sects[i].sh_name, ".text")) {
                result.text_addr = sects[i].sh_addr;
                result.text_size = sects[i].sh_size;
                result.text_offset = sects[i].sh_offset;
            }
        }
    }

    // if the file is in ELF32 format
    else{
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)fbase;
        Elf32_Shdr *sects = (Elf32_Shdr *)(fbase + ehdr->e_shoff);
        int shsize = ehdr->e_shentsize;
        int shnum = ehdr->e_shnum;
        int shstrndx = ehdr->e_shstrndx;
        /* get string table index */
        Elf32_Shdr *shstrsect = &sects[shstrndx];
        char *shstrtab = fbase + shstrsect->sh_offset;

        // put entry point into object
        result.entry_point = ehdr->e_entry;

        int i;
        for(i=0; i<shnum; i++) {
            if(!strcmp(shstrtab+sects[i].sh_name, ".text")) {
                result.text_addr = sects[i].sh_addr;
                result.text_size = sects[i].sh_size;
                result.text_offset = sects[i].sh_offset;
            }
        }
    }
    close(fd);
    return result;
}