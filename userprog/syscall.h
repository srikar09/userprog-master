#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"

void syscall_init (void);
void sys_halt(void);
void sys_exit(int status);
int sys_exec(const char * cmd_line);
int sys_wait(int tid);
bool sys_create(const char * file, unsigned initial_size);
bool sys_remove(const char * file);
int sys_open(const char * file);
int sys_filesize(int fd);
int sys_read(int fd, void * buffer, unsigned size);
int sys_write(int fd, const void * buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
#endif /* userprog/syscall.h */
