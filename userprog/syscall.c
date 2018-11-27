#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <stdbool.h>
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);

//struct lock * lock;

void ptr_check(void * p){

	// check to see if the pointer is null
	if(p == NULL){
		sys_exit(-1);
	}
	// check for pointer range in user virtual address
	if(p >= PHYS_BASE || p <= 0X08048000){
		sys_exit(-1);
	} 
	// check if its a valid entry in pagedir
	if(! pagedir_get_page(thread_current()->pagedir, p)){
		sys_exit(-1);
	}

}
static bool
is_valid_sc_stack(int syscall, void* esp){

	bool retval = true;

	if(syscall == SYS_HALT){
		retval = true;

	}else if(syscall == SYS_EXIT){

		retval = (esp+4) < PHYS_BASE && (esp) > 0x08048000;
		
	}else if(syscall == SYS_EXEC){

		retval = (esp+8) < PHYS_BASE && esp > 0x08048000;

	}else if(syscall == SYS_WAIT){

		retval = (esp+4) < PHYS_BASE && esp > 0x08048000;

	}else if(syscall == SYS_CREATE){

		retval = (esp+12) < PHYS_BASE && esp > 0x08048000;

	}else if(syscall == SYS_REMOVE){

		retval = (esp+4) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_OPEN){

		retval = (esp+8) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_FILESIZE){

		retval = (esp+4) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_READ){
		
		retval = (esp+12) < PHYS_BASE && esp > 0x08048000;	


	}else if(syscall == SYS_WRITE){

		retval = (esp+12) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_SEEK){

		retval = (esp+8) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_TELL){

		retval = (esp+4) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_CLOSE){
		 
		 retval = (esp+4) < PHYS_BASE && esp > 0x08048000;	

	}else if(syscall == SYS_MMAP){			// PROJECT 3, OPTIONALLY PROJECT 4 ONWARDS

	}else if(syscall == SYS_MUNMAP){
		
	}else if(syscall == SYS_CHDIR){			// PROJECT 4 ONWARDS
		
	}else if(syscall == SYS_MKDIR){
		
	}else if(syscall == SYS_READDIR){
		
	}else if(syscall == SYS_ISDIR){
		
	}else if(syscall == SYS_INUMBER){
		
	}

	return retval;

}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static int 
next_open_fd()
{	
	struct thread * t = thread_current();

	int i = 3;
	while(t->fd_table[i]){
		i++;

		if(i == 128){
			return -1;
		}

	}

	return i;
}

void
syscall_init (void)
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{

	//printf ("system call!\n");

	ptr_check(f->esp);

	// Cast to int* to pull 4 bytes instead of just 1
	int syscall_nr = *((int*)(f->esp));		

	//if(!is_valid_sc_stack(syscall_nr, f->esp))
	//	sys_exit(-1);

	//printf("syscallnr: %d\n", syscall_nr);
	// Move esp above syscallnr: pop syscall_nr  

	int eax_initial = f->eax;

	if(syscall_nr == SYS_HALT){

		sys_halt();

	}else if(syscall_nr == SYS_EXIT){

		ptr_check(f->esp+4);
		int status =  *((int*)(f->esp+4));

		sys_exit(status);
		
	}else if(syscall_nr == SYS_EXEC){
		ptr_check(f->esp+4);
		char* cmd_line = *((char**)(f->esp+4));

		ptr_check(cmd_line);
		get_user((uint8_t*)cmd_line);

		if(f->eax != eax_initial)
			return;

		f->eax = sys_exec(cmd_line);

	}else if(syscall_nr == SYS_WAIT){

		ptr_check(f->esp+4);
		int tid = *((int*) (f->esp + 4));

		if(f->eax != eax_initial)
			return;

		f->eax = sys_wait(tid);

	}else if(syscall_nr == SYS_CREATE){

		ptr_check(f->esp+4);
		char* file = *((char**) (f->esp+4));
		ptr_check(file);
		get_user((uint8_t*)file);

		ptr_check(f->esp+8);
		unsigned initial_size = *((unsigned*) (f->esp+8));

		if(f->eax != eax_initial)
			return;

		f->eax = sys_create(file, initial_size);

	}else if(syscall_nr == SYS_REMOVE){

		ptr_check(f->esp+4);
		char* file = *((char**) (f->esp+4));
		ptr_check(file);
		get_user((uint8_t*)file);

		if(f->eax != eax_initial)
			return;

		f->eax = sys_remove(file);		

	}else if(syscall_nr == SYS_OPEN){

		ptr_check(f->esp+4);
		char* file = *((char**) (f->esp+4));
		ptr_check(file);
		get_user((uint8_t*)file);

		if(f->eax != eax_initial)
			return;

		f->eax = sys_open(file);

	}else if(syscall_nr == SYS_FILESIZE){

		ptr_check(f->esp+4);
		int fd = *((int*) (f->esp + 4));

		if(f->eax != eax_initial)
			return;

		f->eax = sys_filesize(fd);

	}else if(syscall_nr == SYS_READ){
		
		ptr_check(f->esp+4);
		int fd = *((int*) (f->esp + 4));

		ptr_check(f->esp+8);
		void * buffer = *((void**) (f->esp + 8));
		put_user((uint8_t*)buffer, (uint8_t)123);
		ptr_check(buffer);

		ptr_check(f->esp+12);
		unsigned size = *((unsigned*) (f->esp + 12));
		// check both ends to make sure whole buffer is street legal
		ptr_check(buffer + size - 1);

		if(f->eax != eax_initial)
			return;

		f->eax = sys_read(fd, buffer, size);


	}else if(syscall_nr == SYS_WRITE){

		ptr_check(f->esp+4);
		int fd = *((int*) (f->esp + 4));

		ptr_check(f->esp+8);
		void * buffer = *((void**) (f->esp + 8));
		get_user((uint8_t*)buffer);
		ptr_check(buffer);

		ptr_check(f->esp+12);
		unsigned size = *((unsigned*) (f->esp + 12));
		// check both ends to make sure whole buffer is street legal
		ptr_check(buffer + size - 1);

		if(f->eax != eax_initial)
			return;

		f->eax = sys_write(fd, buffer, size);

	}else if(syscall_nr == SYS_SEEK){

		ptr_check(f->esp+4);
		int fd = *((int*) (f->esp + 4));

		ptr_check(f->esp + 8);
		unsigned position = *((unsigned*) (f->esp + 8));

		sys_seek(fd, position);

	}else if(syscall_nr == SYS_TELL){

		ptr_check(f->esp + 4);
		int fd = *((int*) (f->esp + 4));

		f->eax = sys_tell(fd);

	}else if(syscall_nr == SYS_CLOSE){
		 
		 ptr_check(f->esp+4);
		 int fd = *((int*) (f->esp + 4));

		 sys_close(fd);

	}else if(syscall_nr == SYS_MMAP){			// PROJECT 3, OPTIONALLY PROJECT 4 ONWARDS

	}else if(syscall_nr == SYS_MUNMAP){
		
	}else if(syscall_nr == SYS_CHDIR){			// PROJECT 4 ONWARDS
		
	}else if(syscall_nr == SYS_MKDIR){
		
	}else if(syscall_nr == SYS_READDIR){
		
	}else if(syscall_nr == SYS_ISDIR){
		
	}else if(syscall_nr == SYS_INUMBER){
		
	}

	//thread_exit ();
}





/*
    Terminates Pintos by calling shutdown_power_off() (declared in "threads/init.h"). 
    This should be seldom used, because you lose some information about possible deadlock situations, etc. 
*/
void sys_halt (void){
	shutdown_power_off();
}

/*
    Terminates the current user program, returning status to the kernel. 
 	If the process's parent waits for it (see below), this is the status that will be returned. 
 	Conventionally, a status of 0 indicates success and nonzero values indicate errors. 
*/
void sys_exit (int status){
	
	struct thread * t = thread_current();
	char * saveptr;
	char * name = strtok_r(t->name, " \n\t", &saveptr);

	t->exit_code = status;
	printf("%s: exit(%d)\n", name, t->exit_code);
	thread_exit();

}

/*	
	Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 
	Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
	Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable.
	You must use appropriate synchronization to ensure this.
*/
int sys_exec (const char *cmd_line){

	return process_execute(cmd_line);
}

/* 
	Waits for a child process pid and retrieves the child's exit status.
	If pid is still alive, waits until it terminates. 
	Then, returns the status that pid passed to exit. 
	If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1.
	It is perfectly legal for a parent process to wait for child processes that 
	have already terminated by the time the parent calls wait
	,but the kernel must still allow the parent to retrieve its child's exit status, 
	or learn that the child was terminated by the kernel.
	wait must fail and return -1 immediately if any of the following conditions is true:
	pid does not refer to a direct child of the calling process. 
	pid is a direct child of the calling process if and only if the calling process received
	pid as a return value from a successful call to exec.
	Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if B is dead. 
	A call to wait(C) by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.
	The process that calls wait has already called wait on pid. 
	That is, a process may wait for any given child at most once. 
	Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or all of their children.
	Your design should consider all the ways in which waits can occur. 
	All of a process's resources, including its struct thread, must be freed whether its parent ever waits for it or not, 
	and regardless of whether the child exits before or after its parent.
	You must ensure that Pintos does not terminate until the initial process exits. 
    The supplied Pintos code tries to do this by calling process_wait() (in "userprog/process.c") from main() (in "threads/init.c"). 
    We suggest that you implement process_wait() according to the comment at the top of the function and then implement the wait system call in terms of process_wait().
    Implementing this system call requires considerably more work than any of the rest.
*/
int sys_wait (int tid){

	return process_wait(tid);
}

/*
	Creates a new file called file initially initial_size bytes in size. 
	Returns true if successful, false otherwise. 
	Creating a new file does not open it: opening the new file is a separate operation which would require a open system call.
*/
bool sys_create (const char *file, unsigned initial_size){
	if(file == NULL || *file == NULL){
		sys_exit(-1);
	}
	//lock_acquire(&lock);
	bool ret = filesys_create(file, initial_size);
	//lock_release(&lock);
	return ret;
}

/*
	Deletes the file called file. Returns true if successful, false otherwise. 
	A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. 
	See Removing an Open File, for details. 
*/
bool sys_remove (const char *file){
	//lock_acquire(&lock);
	bool ret = filesys_remove(file);
	//lock_release(&lock);
	return ret;
}

/*  
	Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
    File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output.
    The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.
    Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.
    When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. 
    Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.
*/
int sys_open (const char *file){

	struct thread * t = thread_current();
	
	int next_fd = next_open_fd();
	struct file * new_file = NULL;
	if(next_fd > 2){
		//lock_acquire(&lock);
		new_file = filesys_open(file);
		//lock_release(&lock);
	}

	if(new_file){
		t->fd_table[next_fd] = new_file; 
	}else{
		return -1;
	}

	return next_fd;
}

/*
	Returns the size, in bytes, of the file open as fd.

*/
int sys_filesize (int fd){

	struct file * f = thread_current()->fd_table[fd];

	return (int)file_length(f);

}

/*
	Reads size bytes from the file open as fd into buffer. 
	Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). 
	Fd 0 reads from the keyboard using input_getc().
*/

int sys_read (int fd, void *buffer, unsigned size){
	char* buff = (char*)buffer;
	
	int current_max_fd = next_open_fd();
	current_max_fd = current_max_fd > 0 ? current_max_fd : 128;

	if(fd == STDIN_FILENO){
		unsigned i = 0;
		while(i < size){
			buff[i] = input_getc();
		}

		return i;
	}else if(fd < 3 || fd >= current_max_fd){
		return -1;
	}

	struct file * f = thread_current()->fd_table[fd];

	return file_read(f, buff, size);

}

/*
    Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
    Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. 
    The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.
    Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. 
    (It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts.
*/     

 int sys_write (int fd, const void *buffer, unsigned size){

 	int current_max_fd = next_open_fd();
 	current_max_fd = current_max_fd > 0 ? current_max_fd : 128;

 	if(fd == STDOUT_FILENO){
 		putbuf((char*)buffer, size);
 		return size;
 	}else if(fd < 3 || fd >= current_max_fd){
 		return -1;
 	}

 	struct file * f = thread_current()->fd_table[fd];
 	
 	return file_write(f, buffer, size);
}

/*
    Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
    A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. 
    A later write extends the file, filling any unwritten gap with zeros. 
    (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) 
    These semantics are implemented in the file system and do not require any special effort in system call implementation.
*/

void sys_seek (int fd, unsigned position){

	if(fd > 2){

		struct file * f = thread_current()->fd_table[fd];

		if(f != NULL)
			f->pos = position;

	}

}

/*
	Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. 
*/	
 
unsigned sys_tell (int fd){

	// Assuming fd > 2, otherwise this makes no sense. No reasonable error code to throw. Also assuming f is valid.

	struct file * f = thread_current()->fd_table[fd];
	return f->pos;

}

 /*
 	Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one
 */
 
void sys_close (int fd){
	if(fd > 2 && fd <= MAX_FILES)
		thread_current()->fd_table[fd] = NULL;

}
 