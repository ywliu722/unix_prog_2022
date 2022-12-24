#include <iostream>
#include <stdio.h>
#include <fstream>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <vector>

using namespace std;

// global variable for filters
bool command = false, type = false, filename = false;
string command_filter = "", type_filter = "", filename_filter = "";

struct process_info{
    int pid;
    string cmd, username;
};

void symbolic_handler(struct process_info *p_info){
    // declare some strings for for loop
    vector<string> type_for_path;
    type_for_path.push_back("cwd");
    type_for_path.push_back("root");
    type_for_path.push_back("exe");

    vector<string> type;
    type.push_back("cwd");
    type.push_back("rtd");
    type.push_back("txt");

    for(int i=0;i<type_for_path.size();i++){
        // get symbolic link target
        char path[256] = {0};
        sprintf(path,"/proc/%d/%s",p_info->pid,type_for_path[i].c_str());
        char target_path[1024]={0};
        int symlink_result = readlink(path,target_path,sizeof(target_path));

        // get inode, file type information
        struct stat file_stat;
        int stat_result = stat(target_path,&file_stat);

        // can get stat successfully and get file type
        string file_type;
        if(stat_result == 0){
            if(S_ISDIR(file_stat.st_mode)){
                file_type = "DIR";
            }
            else if(S_ISCHR(file_stat.st_mode)){
                file_type = "CHR";
            }
            else if(S_ISREG(file_stat.st_mode)){
                file_type = "REG";
            }
            else if(S_ISFIFO(file_stat.st_mode)){
                file_type = "FIFO";
            }
            else if(S_ISSOCK(file_stat.st_mode)){
                file_type = "SOCK";
            }
        }
        else{
            file_type = "unknown";
        }

        // print out result
        if (symlink_result == -1){
            printf("%s\t%d\t%s\t%s\t%s\t%s\t%s (Permission denied)\n",p_info->cmd.c_str(),p_info->pid,p_info->username.c_str(),type[i].c_str(),file_type.c_str(),"",path);
        }
        else{
            printf("%s\t%d\t%s\t%s\t%s\t%ld\t%s\n",p_info->cmd.c_str(),p_info->pid,p_info->username.c_str(),type[i].c_str(),file_type.c_str(),file_stat.st_ino,target_path);
        }
    }
    return;
}

void mem_handler(struct process_info *p_info){
    ifstream ifs;
    string path = "/proc/" + to_string(p_info->pid) + "/maps";
    ifs.open(path);
    if(!ifs.is_open()){
        return;
    }
    string line = "", last_inode = "", last_file = "";
    string current_inode = "", current_file = "";
    while(getline(ifs, line)){
        int pos = 0, index = 0;
        while(1){
            pos = line.find(" ");
            if(pos < 0){
                current_file = line;
                break;
            }
            if(line.substr(0,pos)!=""){
                if(index == 4){
                    current_inode = line.substr(0,pos);
                }
                index++;
            }
            line.erase(0,pos+1);
        }
        if(current_inode == "0" || current_file == last_file){
            continue;
        }

        // get inode, file type information
        struct stat file_stat;
        int stat_result = stat(current_file.c_str(),&file_stat);

        // can get stat successfully and get file type
        string file_type;
        if(stat_result == 0){
            if(S_ISDIR(file_stat.st_mode)){
                file_type = "DIR";
            }
            else if(S_ISCHR(file_stat.st_mode)){
                file_type = "CHR";
            }
            else if(S_ISREG(file_stat.st_mode)){
                file_type = "REG";
            }
            else if(S_ISFIFO(file_stat.st_mode)){
                file_type = "FIFO";
            }
            else if(S_ISSOCK(file_stat.st_mode)){
                file_type = "SOCK";
            }
        }
        else{
            file_type = "unknown";
        }
        last_inode = current_inode;
        last_file = current_file;
        printf("%s\t%d\t%s\t%s\t%s\t%s\t%s\n",p_info->cmd.c_str(),p_info->pid,p_info->username.c_str(),"mem",file_type.c_str(),current_inode.c_str(), current_file.c_str());
    }
    ifs.close();
    return;
}

void fd_handler(struct process_info *p_info){
    char fd_path[256] = {0};
    sprintf(fd_path,"/proc/%d/fd",p_info->pid);
    DIR *dp;
    struct dirent *dirp;
    dp = opendir(fd_path);
    if(dp == NULL){
        printf("%s\t%d\t%s\tNOFD\t\t%s (Permission denied)\n", p_info->cmd.c_str(),p_info->pid,p_info->username.c_str(), fd_path);
        return;
    }
    while( (dirp = readdir(dp)) != NULL){
        int fd = atoi(dirp->d_name);
        if(fd || strcmp(dirp->d_name, "0") == 0){
            char path[256]={0};
            sprintf(path,"/proc/%d/fd/%d",p_info->pid,fd);
            // get symbolic link target
            char target_path[1024]={0};
            int symlink_result = readlink(path,target_path,sizeof(target_path));

            // get inode, file type information
            struct stat file_stat, sym_stat;
            int stat_result = stat(path,&file_stat);
            int sym_result = lstat(path,&sym_stat);

            // file permission
            string file_permission = "";
            if( (sym_stat.st_mode & S_IRUSR) && (sym_stat.st_mode & S_IWUSR) ){
                file_permission = "u";
            }
            else if(sym_stat.st_mode & S_IRUSR){
                file_permission = "r";
            }
            else if(sym_stat.st_mode & S_IWUSR){
                file_permission = "w";
            }

            // file type
            string file_type = "";
            if(S_ISDIR(file_stat.st_mode)){
                file_type = "DIR";
            }
            else if(S_ISCHR(file_stat.st_mode)){
                file_type = "CHR";
            }
            else if(S_ISREG(file_stat.st_mode)){
                file_type = "REG";
            }
            else if(S_ISFIFO(file_stat.st_mode)){
                file_type = "FIFO";
            }
            else if(S_ISSOCK(file_stat.st_mode)){
                file_type = "SOCK";
            }
            printf("%s\t%d\t%s\t%d%s\t%s\t%ld\t%s\n",p_info->cmd.c_str(),p_info->pid,p_info->username.c_str(),fd,file_permission.c_str(),file_type.c_str(),file_stat.st_ino, target_path);
            //cout<< dirp->d_name << file_permission << " " << file_type << " " << file_stat.st_ino << " " << target_path << endl;
        }
    }
    closedir(dp);
}

int main(int argc, char *argv[]){
    // handling arguments
    for(int i = 1; i < argc ; i += 2){
        if(strcmp(argv[i], "-c") == 0){
            command = true;
            command_filter = argv[i+1];
        }
        else if(strcmp(argv[i], "-t") == 0){
            type = true;
            type_filter = argv[i+1];
        }
        else if(strcmp(argv[i], "-f") == 0){
            filename = true;
            filename_filter = argv[i+1];
        }
    }

    // print header
    printf("COMMAND\tPID\tUSER\tFD\tTYPE\tNODE\tNAME\n");

    // read the /proc directory and find all running process
    DIR *dp;
    struct dirent *dirp;
    dp = opendir("/proc");
    while( (dirp = readdir(dp)) != NULL){
        // check if the directory name is pid or not
        int pid = atoi(dirp->d_name);
        if(pid){
            // information for current directory
            struct process_info p_info;
            p_info.pid = pid;

            // get command name
            ifstream ifs;
            string path = "/proc/" + to_string(pid) + "/cmdline";
            ifs.open(path);
            string full_command = "";
            getline(ifs, full_command);
            ifs.close();

            // parsing command name
            if(full_command[0] == '/' || full_command[0] == '.'){
                p_info.cmd = basename(full_command.c_str());
            }
            else if(full_command[0] == '-'){
                p_info.cmd = full_command.substr(1, full_command.size());
            }
            else{
                p_info.cmd = full_command.substr(0, full_command.find(":"));
            }
            
            // get uid of current directory
            struct stat directory_stat;
            path = "/proc/" + to_string(pid);
            stat(path.c_str(), &directory_stat);

            // get username by uid
            struct passwd *pwd;
            pwd = getpwuid(directory_stat.st_uid);
            p_info.username = pwd->pw_name;

            // print out result
            symbolic_handler(&p_info);
            mem_handler(&p_info);
            fd_handler(&p_info);
        }
    }
    closedir(dp);
    return 0;
}