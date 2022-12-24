#include <iostream>
#include <sstream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <elf.h>

using namespace std;

class elf_info{
    public:
        unsigned long int entry_point = -1, text_addr = -1, text_size = -1, text_offset = -1;
};

vector<string> str_split(string &s, char delimeter);
string str_toupper(string &s);
elf_info elf_parsing(string &filename);