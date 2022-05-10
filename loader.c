/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction default_sa;
static unsigned int page_size;
static int fd;



static void sigsegv_handler(int signum, siginfo_t * info, void * p) {

	so_seg_t curr_seg;
	int my_segment = 0;

	/* check if the address that caused the page fault is in one of the file's segments */
	for (int i = 0; i < exec->segments_no; i++) {

		uintptr_t low_address = exec->segments[i].vaddr;
		uintptr_t high_address = exec->segments[i].vaddr + exec->segments[i].mem_size;

		if ((uintptr_t)  info->si_addr >= low_address 
			&& (uintptr_t) info->si_addr < high_address) {

			my_segment = 1;
			curr_seg = exec->segments[i];

			break;
		}
	}

	if (!my_segment) { 
		default_sa.sa_handler(signum);
		return;
	}

	int page_num = ((uintptr_t) info->si_addr - curr_seg.vaddr) / page_size;

	/* the page fault was caused by an address that is not mapped in RAM */
    if (info->si_code == SEGV_MAPERR) {

		/* map page */
		
		void *address = (void*)curr_seg.vaddr + page_num * page_size;
		address =  mmap (address, page_size, PROT_NONE,
			MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

		if (address == MAP_FAILED) {
			default_sa.sa_handler(signum);
			return;
		}

		/* init page with data */

		mprotect(address, page_size, PROT_READ | PROT_WRITE);
		memset(address, 0, page_size);

		unsigned int page_address = page_num * page_size;
		unsigned int to_read = page_size;

		if (page_address > curr_seg.file_size) {
			to_read = 0;
		} else if (curr_seg.file_size - page_address < page_size) {
			to_read = curr_seg.file_size - page_address;
		}
		
		if (to_read != 0) {
			if (lseek(fd, curr_seg.offset + page_address , SEEK_SET) < 0) {
				default_sa.sa_handler(signum);
				return;
			}
			long amount_read = read(fd, address, to_read);	
		} 
		
		mprotect(address, page_size, curr_seg.perm);

	/* the page fault was caused by a forbidden operation on a memory segment*/
	} else if (info->si_code == SEGV_ACCERR) {
		default_sa.sa_handler(signum);
	}
}

int so_init_loader(void)
{	
	page_size = getpagesize();

	/* init a sigaction structure for handling the SIGSEGV signal*/

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sa.sa_flags   = SA_SIGINFO; 
	sa.sa_sigaction = sigsegv_handler;
	
	return sigaction(SIGSEGV, &sa, &default_sa);
}

int so_execute(char *path, char *argv[])
{	
	fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
