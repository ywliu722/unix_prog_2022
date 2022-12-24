#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <capstone/capstone.h>

#include "hw4.hpp"
#include "utils.hpp"

using namespace std;

// state of program
bool isQuit = false;
string state = "NOT_LOADED";

// program name and script name
bool isScript = false;
string prog_name = "";
string script_name = "";

// program information
int prog_size = 0;
char *prog = NULL;
elf_info file_info;
pid_t pid = 0;
struct user_regs_struct regs;
map<string, unsigned long long int> regs_map;
vector<string> regs_name{"rax", "rbx", "rcx", "rdx",
                         "r8", "r9", "r10", "r11",
                         "r12", "r13", "r14", "r15",
                         "rdi", "rsi", "rbp", "rsp",
                         "rip", "flags"};

int current_breakpoint_id = 0;
vector<breakpoint_info> breakpoints;
int hit_id = -1;

// 0: pass through the breakpoint, 1: hit the break point now, 2: none of them
int check_state(){
    int status;
    // check if the child process is stopped or exited
    waitpid(pid, &status, 0);
    // check if hit the break point
    if(WIFSTOPPED(status)){
        // not caused by hitting the breakpoint (SIGTRAP)
        if(WSTOPSIG(status) != SIGTRAP){
            cerr << "** child process " << pid << " stopped by signal (code " << WSTOPSIG(status) << ")" <<endl;
            return 2;
        }

        // we have pass through the breakpoint and the breakpoint is needed to be restore
        if(hit_id != -1){
            return 0;
        }

        // get the rip in register and restore it to execute the original instruction
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        reg_struct_to_map();
        for(int i = 0; i < breakpoints.size(); i++){
            // found the current breakpoint
            if(breakpoints[i].addr == regs_map["rip"] - 1){
                hit_id = breakpoints[i].id;
                cerr << "** breakpoint @";
                // parsing the original instruction
                if(prog == NULL){
                    import_prog();
                }

                unsigned long long int file_addr = breakpoints[i].addr - file_info.text_addr + file_info.text_offset;
                unsigned char *pos = (unsigned char *)prog + file_addr;

                csh cshandle;
                cs_insn *insn;
                size_t count;
                cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle);
                count = cs_disasm(cshandle, pos, 16*16, breakpoints[i].addr, 0, &insn);
                string bytes = "";
                for(int j = 0; j < insn[0].size; j++){
                    stringstream ss;
                    ss << setfill('0') << setw(2) << hex << (int)insn[0].bytes[j] << setfill(' ') << dec << " ";
                    bytes += ss.str();
                }
                cerr << setw(12) <<  hex << insn[0].address << dec << ": " << left << setw(31) << bytes << setw(7) << insn[0].mnemonic << right << insn[0].op_str << endl;

                // restore the rip and the instruction
                regs_map["rip"]--;
                reg_map_to_struct();
                ptrace(PTRACE_SETREGS, pid, 0, &regs);

                long code = ptrace(PTRACE_PEEKTEXT, pid, breakpoints[i].addr, 0);
                ptrace(PTRACE_POKETEXT, pid, breakpoints[i].addr, (code & 0xffffffffffffff00) | (breakpoints[i].original_byte & 0xff));

                return 1;
            }
        }

    }
    // check if the program exited
    if(WIFEXITED(status)){
        // terminated by a signal
        if(WIFSIGNALED(status)){
            cerr << "** child process " << pid << "terminated by sinal (code " << WTERMSIG(status) << ")" << endl;
        }
        // terminated normally
        else{
            cerr << "** child process " << pid << " terminiated normally (code " << status << ")" << endl;
        }
        pid = 0;
        state = "LOADED";
        return 2;
    }
    return 2;
}

void import_prog(){
    ifstream file(prog_name, ios::binary | ios::ate);
    streamsize size = file.tellg();
    prog_size = size + 1;
    file.seekg(0, ios::beg);

    prog = new char[prog_size];
    file.read(prog, size);
    prog[size] = 0;
    file.close();
}

void reg_struct_to_map(){
    regs_map["rax"] = regs.rax;
    regs_map["rbx"] = regs.rbx;
    regs_map["rcx"] = regs.rcx;
    regs_map["rdx"] = regs.rdx;

    regs_map["r8"] = regs.r8;
    regs_map["r9"] = regs.r9;
    regs_map["r10"] = regs.r10;
    regs_map["r11"] = regs.r11;

    regs_map["r12"] = regs.r12;
    regs_map["r13"] = regs.r13;
    regs_map["r14"] = regs.r14;
    regs_map["r15"] = regs.r15;

    regs_map["rdi"] = regs.rdi;
    regs_map["rsi"] = regs.rsi;
    regs_map["rbp"] = regs.rbp;
    regs_map["rsp"] = regs.rsp;

    regs_map["rip"] = regs.rip;
    regs_map["flags"] = regs.eflags;
}

void reg_map_to_struct(){
    regs.rax = regs_map["rax"];
    regs.rbx = regs_map["rbx"];
    regs.rcx = regs_map["rcx"];
    regs.rdx = regs_map["rdx"];

    regs.r8 = regs_map["r8"];
    regs.r9 = regs_map["r9"];
    regs.r10 = regs_map["r10"];
    regs.r11 = regs_map["r11"];

    regs.r12 = regs_map["r12"];
    regs.r13 = regs_map["r13"];
    regs.r14 = regs_map["r14"];
    regs.r15 = regs_map["r15"];

    regs.rdi = regs_map["rdi"];
    regs.rsi = regs_map["rsi"];
    regs.rbp = regs_map["rbp"];
    regs.rsp = regs_map["rsp"];

    regs.rip = regs_map["rip"];
    regs.eflags = regs_map["flags"];
}

void restore_breakpoint(){
    for(int i = 0; i < breakpoints.size(); i++){
        if(breakpoints[i].id == hit_id){
            long code = ptrace(PTRACE_PEEKTEXT, pid, breakpoints[i].addr, 0);
            ptrace(PTRACE_POKETEXT, pid, breakpoints[i].addr, (code & 0xffffffffffffff00) | 0xcc);
            hit_id = -1;
            break;
        }
    }
}

void breakpoint(string &target){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }

    unsigned long long int addr = stoull(target, NULL, 16);

    // check if the target address is in the .text section
    if(addr < file_info.text_addr || addr > file_info.text_addr + file_info.text_size - 1){
        cerr << "** the address is out of the range of the text segment" <<endl;
        return;
    }

    long code = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    ptrace(PTRACE_POKETEXT, pid, addr, (code & 0xffffffffffffff00) | 0xcc);

    breakpoint_info bp;
    bp.id = current_breakpoint_id;
    bp.addr = addr;
    bp.original_byte = (unsigned char) (code & 0xff);
    breakpoints.push_back(bp);

    current_breakpoint_id++;
}

void cont(){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    if(hit_id != -1){
        // execute the breakpoint instruction and restore the breakpoint to 0xcc
        si();
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    check_state();
}

void del(string &target_id){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    int id = stoi(target_id);
    int i = 0;
    for(auto it = breakpoints.begin(); it != breakpoints.end(); it++){
        if(id == i){
            long code = ptrace(PTRACE_PEEKTEXT, pid, (*it).addr, 0);
            ptrace(PTRACE_POKETEXT, pid, (*it).addr, (code & 0xffffffffffffff00) | ((*it).original_byte & 0xff));
            breakpoints.erase(it);
            cerr << "** breakpoint " << id << " deleted." <<endl;
            return;
        }
        i++;
    }
    cerr << "** no breaking number " << id << "." << endl;
}

void disasm(string &target){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    unsigned long long int addr = stoull(target, NULL, 16);
    if(prog == NULL){
        import_prog();
    }

    unsigned long long int file_addr = addr - file_info.text_addr + file_info.text_offset;
    unsigned long long int read_size = file_info.text_addr + file_info.text_size - addr;
    unsigned char *pos = (unsigned char *)prog + file_addr;

    csh cshandle;
    cs_insn *insn;
    size_t count;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle);
    count = cs_disasm(cshandle, pos, read_size, addr, 0, &insn);
    for(int i = 0; i < count; i++){
        if(i > 9){
            break;
        }
        string bytes = "";
        for(int j = 0; j < insn[i].size; j++){
            stringstream ss;
            ss << setfill('0') << setw(2) << hex << (int)insn[i].bytes[j] << setfill(' ') << dec << " ";
            bytes += ss.str();
        }
        cout << setw(12) <<  hex << insn[i].address << dec << ": " << left << setw(31) << bytes << setw(7) << insn[i].mnemonic << right << insn[i].op_str << endl;
    }
    cs_close(&cshandle);
    if(count < 10){
        cerr << "** the address is out of the range of the text segment" << endl;
    }
}

void dump(string &target){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    unsigned long long int addr = stoull(target, NULL, 16);
    for(int i = 0; i < 5; i++){
        vector<int> bytes;

        // print out mem_addr
        cout << setw(12) << hex << addr << ": " << dec;

        // get value from mem
        long code_1 = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        long code_2 = ptrace(PTRACE_PEEKTEXT, pid, addr + 8, 0);

        // process values from mem
        for(int i = 0; i < 8 ; i++){
            bytes.push_back(code_1 % 256);
            code_1 /= 256;
        }
        for(int i = 0; i < 8 ; i++){
            bytes.push_back(code_2 % 256);
            code_2 /= 256;
        }
        
        // print out hex value
        for(int i = 0; i < bytes.size(); i++){
            cout << setfill('0') << setw(2) << hex << bytes[i] << setfill(' ') << dec << " ";
        }

        // print out printable vharacters
        cout << " |";
        for(int i = 0; i < bytes.size(); i++){
            if(bytes[i] < 32 || bytes[i] > 126){
                cout << ".";
            }
            else{
                cout << char(bytes[i]);
            }
        }
        cout << "|" << endl;
        addr += 16;
    }
}

void q(){
    if(pid > 0){
        kill(pid, SIGTERM);
    }
    if(prog != NULL){
        delete []prog;
        prog = NULL;
    }
}

void get(string &target){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    reg_struct_to_map();
    if(regs_map.count(target)){
        cout << target << " = " << regs_map[target] << " (0x" << hex << regs_map[target] << ")" << dec << endl;
    }
    else{
        cerr << "** invalid register" <<endl;
    }

}

void getregs(){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    reg_struct_to_map();
    for(int i = 0; i < regs_name.size() -1; i++){
        cout << setw(3) << left << str_toupper(regs_name[i]) << " " << setw(18) << left << hex << regs_map[regs_name[i]] << right << dec;
        if(i % 4 == 3){
            cout << endl;
        }
    }
    cout << str_toupper(regs_name.back()) << " " << setfill('0') << setw(16) << right << hex << regs_map[regs_name.back()] << dec << setfill(' ') << endl;
}

void help(){
    cout<<"- break {instruction-address}: add a break point"<<endl;
    cout<<"- cont: continue execution"<<endl;
    cout<<"- delete {break-point-id}: remove a break point"<<endl;
    cout<<"- disasm addr: disassemble instructions in a file or a memory region"<<endl;
    cout<<"- dump addr: dump memory content"<<endl;
    cout<<"- exit: terminate the debugger"<<endl;
    cout<<"- get reg: get a single value from a register"<<endl;
    cout<<"- getregs: show registers"<<endl;
    cout<<"- help: show this message"<<endl;
    cout<<"- list: list break points"<<endl;
    cout<<"- load {path/to/a/program}: load a program"<<endl;
    cout<<"- run: run the program"<<endl;
    cout<<"- vmmap: show memory layout"<<endl;
    cout<<"- set reg val: get a single value to a register"<<endl;
    cout<<"- si: step into instruction"<<endl;
    cout<<"- start: start the program and stop at the first instruction"<<endl;
}

void list(){
    for(int i = 0; i < breakpoints.size(); i++){
        cout << setw(3) << i << ":" << setw(8) << hex << breakpoints[i].addr << dec << endl;
    }
}

void load(){
    if (state != "NOT_LOADED") {
        cerr << "** state must be NOT LOADED." << endl;
        return;
    }
    file_info = elf_parsing(prog_name);
    if(file_info.entry_point < 0 || file_info.text_addr < 0 || file_info.text_size < 0){
        cerr<<"** Cannot load program '"<<prog_name<<"'."<<endl;
        return;
    }
    cerr << "** program '" << prog_name << hex << "' loaded. entry point 0x" << file_info.entry_point << endl << dec;
    state = "LOADED";
}

void run(){
    if(state == "NOT_LOADED"){
        cerr << "** state must be LOADED or RUNNING." << endl;
    }
    else if(state == "LOADED"){
        start();
        cont();
    }
    else{
        cerr << "** program " << prog_name << " is already running" <<endl;
        cont();
    }
}

void vmmap(){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    ifstream ifs("/proc/" + to_string(pid) + "/maps");
    string input = "";
    while(getline(ifs, input)){
        vector<string> split = str_split(input, ' ');
        vector<string> memaddr = str_split(split[0], '-');
        cout << setfill('0') << setw(16) << memaddr[0] << "-" << setw(16) << memaddr[1] << " " << split[1].substr(0,3) << " " << setfill(' ') << setw(8) << left << hex << stol(split[2], NULL, 16) << right << dec << " ";
        if(split.size()>5){
            cout<<split[5];
        }
        cout<<endl;
    }
    ifs.close();
}

void set(string &target, string &value){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    reg_struct_to_map();
    if(regs_map.count(target)){
        regs_map[target] = stoull(value, NULL, 16);
        reg_map_to_struct();
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
    }
    else{
        cerr << "** invalid register" <<endl;
    }
}

void si(){
    if(state != "RUNNING"){
        cerr << "** state must be RUNNING" << endl;
        return;
    }
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

    // if we just hit the breakpoint and just execute the breakpoint instruction
    if(check_state() == 0 && hit_id != -1){
        restore_breakpoint();
    }
}

void start(){
    // check if the pid is zero or not
    if(pid){
        cerr << "** program " << prog_name << " is already running" <<endl;
        return;
    }

    // check the state
    if(state != "LOADED"){
        cerr << "** state must be LOADED." << endl;
        return;
    }

    pid = fork();

    if(pid < 0){
        cerr << "** fork error" <<endl;
        return;
    }
    // child process
    if(pid == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
            cerr << "** ptrace error" <<endl;
        }
        char *argv[] = {NULL};
        execvp(prog_name.c_str(), argv);
    }
    // parent process
    else{
        int status;
        if(waitpid(pid, &status, 0) < 0){
            cerr << "** waitpid error" <<endl;
        }
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

        // set the breakpoints
        for(int i = 0; i < breakpoints.size(); i++){
            long code = ptrace(PTRACE_PEEKTEXT, pid, breakpoints[i].addr, 0);
            ptrace(PTRACE_POKETEXT, pid, breakpoints[i].addr, (code & 0xffffffffffffff00) | 0xcc);
        }
        cerr << "** pid " << pid << endl;
        state = "RUNNING";
    }
}

void command_determine(string &input){
    // check that the input is blank or not
    if(input.size()<1){
        return;
    }

    // split the input
    vector<string> split_input = str_split(input, ' ');

    // break
    if(split_input[0] == "break" || split_input[0] == "b"){
        if(split_input.size() < 2){
            cerr << "** no address is given" <<endl;
            return;
        }
        breakpoint(split_input[1]);
    }
    // continue
    else if(split_input[0] == "cont" || split_input[0] == "c"){
        cont();
    }
    // delete
    else if(split_input[0] == "delete"){
        if(split_input.size() < 2){
            cerr << "** no break point id is given" <<endl;
            return;
        }
        del(split_input[1]);
    }
    // disassemble
    else if(split_input[0] == "disasm" || split_input[0] == "d"){
        if(split_input.size() < 2){
            cerr << "** no addr is given" <<endl;
            return;
        }
        disasm(split_input[1]);
    }
    // dump
    else if(split_input[0] == "dump" || split_input[0] == "x"){
        if(split_input.size() < 2){
            cerr << "** no addr is given" <<endl;
            return;
        }
        dump(split_input[1]);
    }
    // exit
    else if(split_input[0] == "exit" || split_input[0] == "q"){
        q();
        isQuit = true;
    }
    // get
    else if(split_input[0] == "get" || split_input[0] == "g"){
        if(split_input.size() < 2){
            cerr << "** no register is given" <<endl;
            return;
        }
        get(split_input[1]);
    }
    // getregs
    else if(split_input[0] == "getregs"){
        getregs();
    }
    // help
    else if(split_input[0] == "help" || split_input[0] == "h"){
        help();
    }
    // list
    else if(split_input[0] == "list" || split_input[0] == "l"){
        list();
    }
    // load
    else if(split_input[0] == "load"){
        prog_name = split_input[1];
        load();
    }
    // run
    else if(split_input[0] == "run" || split_input[0] == "r"){
        run();
    }
    // vmmap
    else if(split_input[0] == "vmmap" || split_input[0] == "m"){
        vmmap();
    }
    // set
    else if(split_input[0] == "set" || split_input[0] == "s"){
        if(split_input.size() < 3){
            cerr << "** some argument missing" <<endl;
            return;
        }
        set(split_input[1], split_input[2]);
    }
    // si
    else if(split_input[0] == "si"){
        si();
    }
    // start
    else if(split_input[0] == "start"){
        start();
    }
    else{
        cerr<<"** invalid command"<<endl;
    }
}

void useScript(){
    ifstream ifs(script_name);
    string input = "";
    while(getline(ifs, input)){
        command_determine(input);
    }
    ifs.close();
}

int main(int argc, char* argv[]){
    // parsing arguments
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-s") == 0){
            isScript = true;
            script_name = argv[i+1];
            i++;
        }
        else if(strcmp(argv[i], "") != 0){
            prog_name = argv[i];
            load();
        }
    }

    // using script as input
    if(isScript){
        useScript();
        return 0;
    }
    
    // use user input
    while(true){
        cerr<< "sdb> ";
        string input = "";
        getline(cin, input);
        command_determine(input);
        if(isQuit){
            return 0;
        }
    }
}