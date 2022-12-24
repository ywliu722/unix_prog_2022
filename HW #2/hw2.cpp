#include <stdio.h>
#include <unistd.h>
#include <string>

using namespace std;
int main(int argc, char *argv[]){
    // check if there is any argument
    if(argc < 2){
        printf("no command given.\n");
        return 0;
    }

    int opt;
    string so_path = "./logger.so";
    string output_path = "stderr";
    string command = "";

    // parsing arguments
    while((opt = getopt(argc, argv, "p:o:-:")) != -1){
        switch(opt){
            case 'p':
                so_path = optarg;
                break;
            case 'o':
                output_path = optarg;
                break;
            case '-':
                break;
            default:
                printf("usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
                printf("        -p: set the path to logger.so, default = ./logger.so\n");
                printf("        -o: print output to file, print to \"stderr\" if no file specified\n");
                printf("        --: separate the arguments for logger and for the command\n");
                return 0;
        }
    }
    
    // generate execution command
    command = "LD_PRELOAD=" + so_path + " OUTPUT_FILE=" + output_path;
    for(int i = optind;i < argc;i++){
        command = command + " " + argv[i];
    }

    // execute command
    system(command.c_str());
    return 0;
}