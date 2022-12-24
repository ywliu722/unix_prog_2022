#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

bool isInitialized = false;
void *handle = NULL;
FILE *output_file = NULL;

void initialize(){
    handle = dlopen("libc.so.6", RTLD_LAZY);
    if(handle == NULL){
        exit(0);
    }
    char *output = getenv("OUTPUT_FILE");
    if(strcmp(output, "stderr") == 0){
        output_file = stderr;
    }
    else{
        typedef FILE*(*fopen_t)(const char *filename, const char *mode);
        fopen_t old_fopen = (fopen_t) dlsym(handle, "fopen");
        output_file = old_fopen(output, "a");
        setbuf(output_file, NULL);
    }
}

int chmod(const char *pathname, mode_t mode){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get absolute file path
    char absolute_path[256] = {0};
    char *success = realpath(pathname, absolute_path);
    if(success == NULL){
        strcpy(absolute_path, "string untouched");
    }

    // define function type and get the original function
    typedef int(*chmod_type)(const char *pathname, mode_t mode);
    chmod_type old_chmod = (chmod_type) dlsym(handle, "chmod");
    int return_value = old_chmod(pathname, mode);
    fprintf(output_file, "[logger] chmod(\"%s\", %o) = %d\n", absolute_path, mode, return_value);

    return return_value;
}

int chown(const char *pathname, uid_t owner, gid_t group){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get absolute file path
    char absolute_path[256] = {0};
    char *success = realpath(pathname, absolute_path);
    if(success == NULL){
        strcpy(absolute_path, "string untouched");
    }

    // define function type and get the original function
    typedef int(*chown_type)(const char *pathname, uid_t owner, gid_t group);
    chown_type old_chown = (chown_type) dlsym(handle, "chown");
    int return_value = old_chown(pathname, owner, group);
    fprintf(output_file, "[logger] chown(\"%s\", %u, %u) = %d\n", absolute_path, owner, group, return_value);

    return return_value;
}

int open(const char *pathname, int flags, mode_t mode){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // define function type and get original function
    typedef int(*open_type)(const char *pathname, int flags, mode_t mode);
    open_type old_open = (open_type) dlsym(handle, "open");
    int return_value = old_open(pathname, flags, mode);

    // get absolute file path
    char absolute_path[256] = {0};
    char *success = realpath(pathname, absolute_path);
    if(success == NULL){
        strcpy(absolute_path, "string untouched");
    }

    fprintf(output_file, "[logger] open(\"%s\", %o, %o) = %d\n", absolute_path, flags, mode, return_value);

    return return_value;
}

ssize_t read(int fd, void *buf, size_t count){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fd);
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    // define function type and get the original function
    typedef ssize_t(*read_type)(int fd, void *buf, size_t count);
    read_type old_read = (read_type) dlsym(handle, "read");
    size_t return_value = old_read(fd, buf, count);

    // print out result
    fprintf(output_file, "[logger] read(\"%s\", \"", target_path);
    char *char_ptr = (char*) buf;
    for(int i=0; i<return_value; i++){
        if(i>32){
            break;
        }
        if(isprint(char_ptr[i])){
            fprintf(output_file, "%c", char_ptr[i]);
        }
        else{
            fprintf(output_file, ".");
        }
    }
    fprintf(output_file, "\", %ld) = %ld\n", count, return_value);

    return return_value;
}

ssize_t write(int fd, const void *buf, size_t count){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fd);
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    // define function type and get the original function
    typedef ssize_t(*write_type)(int fd, const void *buf, size_t count);
    write_type old_write = (write_type) dlsym(handle, "write");
    size_t return_value = old_write(fd, buf, count);

    // print out result
    fprintf(output_file, "[logger] write(\"%s\", \"", target_path);
    char *char_ptr = (char*) buf;
    for(int i=0; i<return_value; i++){
        if(i>32){
            break;
        }
        if(isprint(char_ptr[i])){
            fprintf(output_file, "%c", char_ptr[i]);
        }
        else{
            fprintf(output_file, ".");
        }
    }
    fprintf(output_file, "\", %ld) = %ld\n", count, return_value);

    return return_value;
}

int close(int fd){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fd);
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    // define function type and get the original function
    typedef int(*close_type)(int fd);
    close_type old_close = (close_type) dlsym(handle, "close");
    int return_value = old_close(fd);
    fprintf(output_file, "[logger] close(\"%s\") = %d\n", target_path, return_value);

    return return_value;
}

int creat(const char *pathname, mode_t mode){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // define function type and get the original function
    typedef int(*creat_type)(const char *pathname, mode_t mode);
    creat_type old_creat = (creat_type) dlsym(handle, "creat");
    int return_value = old_creat(pathname, mode);

    // get absolute file path
    char absolute_path[256] = {0};
    char *success = realpath(pathname, absolute_path);
    if(success == NULL){
        strcpy(absolute_path, "string untouched");
    }

    fprintf(output_file, "[logger] creat(\"%s\", %o) = %d\n", absolute_path, mode, return_value);

    return return_value;
}

int rename(const char *oldpath, const char *newpath){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get absolute path of old file name
    char old_absolute_path[256] = {0};
    char *old_success = realpath(oldpath, old_absolute_path);
    if(old_success == NULL){
        strcpy(old_absolute_path, "string untouched");
    }

    // define function type and get the original function
    typedef int(*rename_type)(const char *oldpath, const char *newpath);
    rename_type old_rename = (rename_type) dlsym(handle, "rename");
    int return_value = old_rename(oldpath, newpath);

    // get absolute path of new file name
    char new_absolute_path[256] = {0};
    char *new_success = realpath(newpath, new_absolute_path);
    if(new_success == NULL){
        strcpy(new_absolute_path, "string untouched");
    }

    fprintf(output_file, "[logger] rename(\"%s\", \"%s\") = %d\n", old_absolute_path, new_absolute_path, return_value);

    return return_value;
}

int remove(const char *pathname){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get absolute file path
    char absolute_path[256] = {0};
    char *success = realpath(pathname, absolute_path);
    if(success == NULL){
        strcpy(absolute_path, "string untouched");
    }

    // define function type and get the original function
    typedef int(*remove_type)(const char *pathname);
    remove_type old_remove = (remove_type) dlsym(handle, "remove");
    int return_value = old_remove(pathname);
    fprintf(output_file, "[logger] remove(\"%s\") = %d\n", absolute_path, return_value);

    return return_value;
}

FILE *fopen(const char *filename, const char *mode){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // define function type and get the original function
    typedef FILE*(*fopen_type)(const char *filename, const char *mode);
    fopen_type old_fopen = (fopen_type) dlsym(handle, "fopen");
    FILE *return_value = old_fopen(filename, mode);

    // get absolute file path
    char absolute_path[256] = {0};
    char *success = realpath(filename, absolute_path);
    if(success == NULL){
        strcpy(absolute_path, "string untouched");
    }

    fprintf(output_file, "[logger] fopen(\"%s\", \"%s\") = %p\n", absolute_path, mode, return_value);

    return return_value;
}

int fclose(FILE *stream){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fileno(stream));
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    // define function type and get the original function
    typedef int(*fclose_type)(FILE *stream);
    fclose_type old_fclose = (fclose_type) dlsym(handle, "fclose");
    int return_value = old_fclose(stream);
    fprintf(output_file, "[logger] fclose(\"%s\") = %d\n", target_path, return_value);

    return return_value;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fileno(stream));
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    // define function type and get the original function
    typedef size_t(*fread_type)(void *ptr, size_t size, size_t nmemb, FILE *stream);
    fread_type old_fread = (fread_type) dlsym(handle, "fread");
    size_t return_value = old_fread(ptr, size, nmemb, stream);

    // print out result
    fprintf(output_file, "[logger] fread(%s\"", "");
    char *char_ptr = (char*) ptr;
    for(int i=0; i<return_value; i++){
        if(i>32){
            break;
        }
        if(isprint(char_ptr[i])){
            fprintf(output_file, "%c", char_ptr[i]);
        }
        else{
            fprintf(output_file, ".");
        }
    }
    fprintf(output_file, "\", %ld, %ld, \"%s\") = %ld\n", size, nmemb, target_path, return_value);

    return return_value;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }
    if(stream == NULL){
        printf("NONO\n");
        return 0;
    }
    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fileno(stream));
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    
    // define function type and get the original function
    typedef size_t(*fwrite_type)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    fwrite_type old_fwrite = (fwrite_type) dlsym(handle, "fwrite");
    size_t return_value = old_fwrite(ptr, size, nmemb, stream);
    

    // print out result
    fprintf(output_file, "[logger] fwrite(%s\"", "");  
    char *char_ptr = (char*) ptr;
    for(int i=0;i<5;i++){
        if(isprint(char_ptr[i])){
            fprintf(output_file, "%c", char_ptr[i]);
        }
        else{
            fprintf(output_file,".");
        }
    }
    fprintf(output_file, "\", %zu, %zu, \"%s\") = %zu\n", size, nmemb, target_path, return_value);  

    return return_value;
}

FILE *tmpfile(void){
    // check the needed pointers are initialized or not
    if(!isInitialized){
        initialize();
    }

    // define function type and get the original function
    typedef FILE*(*tmpfile_type)(void);
    tmpfile_type old_tmpfile = (tmpfile_type) dlsym(handle, "tmpfile");
    FILE *return_value = old_tmpfile();
    fprintf(output_file, "[logger] tmpfile() = %p\n", return_value);

    // get symbolic link target
    char path[256]={0};
    sprintf(path,"/proc/self/fd/%d", fileno(return_value));
    char target_path[1024]={0};
    int symlink_result = readlink(path,target_path,sizeof(target_path));

    return return_value;
}
