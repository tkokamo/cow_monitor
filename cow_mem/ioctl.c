/* ioctl.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "cow_mem.h"

int main()
{
  int fd;
  int ret_val;
  void *addr;
  struct cow_monitor cow;
  
  fd = open(DEVICE_FILE_NAME, 0);
  if (fd < 0) {
    printf("Can't open device file: %s\n", DEVICE_FILE_NAME);
    exit(1);
  }

  addr = mmap(NULL, 100, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  

  cow.pid = (pid_t)getpid();
  cow.addr = (void *)addr;
  cow.len = 100;
  ret_val = ioctl(fd, IOCTL_COW_MONITOR, &cow);
  if (ret_val < 0) {
    printf("ioctl failed: %d\n", ret_val);
    sleep(10);
    exit(1);
  }

  close(fd);

  //  printf("[+] getuid() = %d\n", getuid());
  //execl("/bin/sh", "sh", NULL);
}
