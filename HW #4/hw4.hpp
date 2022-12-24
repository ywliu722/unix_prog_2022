using namespace std;

class breakpoint_info{
    public:
        int id;
        unsigned long long int addr;
        unsigned char original_byte;
};

int check_state();
void import_prog();
void reg_struct_to_map();
void reg_map_to_struct();
void restore_breakpoint();

void breakpoint(string &target);
void cont();
void del(string &target_id);
void disasm(string &target);
void dump(string &target);
void q();
void get(string &target);
void getregs();
void help();
void list();
void load();
void run();
void vmmap();
void set(string &target, string &value);
void si();
void start();
void command_determine(string &input);