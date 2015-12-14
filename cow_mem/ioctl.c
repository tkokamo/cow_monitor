/* ioctl.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "cow_mem.h"

void *cow_mem(pid_t pid, void *addr, unsigned long len)
{
  int fd;
  struct cow_monitor cow;
  void *ret_val;
  fd = open(DEVICE_FILE_NAME, 0);
  if (fd < 0) {
    printf("Can't open device file: %s\n", DEVICE_FILE_NAME);
    exit(1);
  }
  
  cow.pid = pid;
  cow.addr = (void *)addr;
  cow.len = len;
  ret_val = ioctl(fd, IOCTL_COW_MONITOR, &cow);
  if (ret_val < 0) {
    printf("ioctl failed: %ld\n", ret_val);
    sleep(10);
    exit(1);
  }
  close(fd);

  return cow.ret_addr;
}

int main()
{

  void *ret_val;
  void *addr;
  char *p;

  addr = mmap(NULL, 1000000, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ((char *)addr)[90000] = 'a';
  printf("addr = %c\n", ((char *)addr)[90000]);

  ret_val = cow_mem(getpid(), addr, 1000000);
  
  //  ((char *)ret_val)[0] = 'a';
  //printf("ret_val = %c\n", ((char *)ret_val)[0]);
  printf("addr = %p, ret = %p\n", addr, ret_val);
  ((char *)addr)[90000] = 'b';
  p = ret_val;
  
  printf("p[0] = %c\n", p[90000]);
  p[9] = 'c';
  printf("a[0] = %c, p[0] = %c\n", ((char *)addr)[90000], p[90000]);

  sleep(100);

  //  printf("[+] getuid() = %d\n", getuid());
  //execl("/bin/sh", "sh", NULL);
}
