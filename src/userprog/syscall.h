#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "filesys/directory.h"

void syscall_init (void);

void syscall_halt(struct intr_frame *f);

void syscall_exit(struct intr_frame *f,int argsNum);

void syscall_exec(struct intr_frame *f,int argsNum);

void syscall_wait(struct intr_frame *f,int argsNum);

void syscall_create(struct intr_frame *f,int argsNum);

void syscall_remove(struct intr_frame *f,int argsNum);

void syscall_open(struct intr_frame *f,int argsNum);

void syscall_filesize(struct intr_frame *f,int argsNum);

void syscall_read(struct intr_frame *f,int argsNum);

void syscall_write(struct intr_frame *f,int argsNum);

void syscall_seek(struct intr_frame *f,int argsNum);

void syscall_tell(struct intr_frame *f,int argsNum);

void syscall_close(struct intr_frame *f,int argsNum);

void syscall_chdir(struct intr_frame *f,int argsNum);
void syscall_mkdir(struct intr_frame *f,int argsNum);
void syscall_readdir(struct intr_frame *f,int argsNum);
void syscall_isdir(struct intr_frame *f,int argsNum);
void syscall_inumber(struct intr_frame *f,int argsNum);


int currentFd(struct thread *cur);

struct file* getFile(int fd,struct thread *cur);

void elemFile(struct file *file);

void allClose(struct thread *cur);

bool isdir_by_fd(int fd);

struct fd_elem{
	struct list_elem elem;
	struct thread* owner;
	struct file *file;
	char* filename;
	int fd;
	bool isEXE;
 
        struct dir* dir;
        bool isdir;
};

#endif /* userprog/syscall.h */
