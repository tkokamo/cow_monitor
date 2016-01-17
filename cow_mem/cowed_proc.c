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
  unsigned long long i;
  
  addr = mmap(NULL, 1000000000, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  
  printf("%d %lld\n", getpid(), (unsigned long long)addr);
  for (i = 0; i < 1000000000/4096; i++) {
    ((char *)addr)[(unsigned long long)i*4096] = 'a';
  }
  printf("addr[...] = %c\n", ((char *)addr)[4096*((unsigned long long)(1000000000/4096 - 10))]);
  printf("addr = %c\n", ((char *)addr)[4096]);
  
  sleep(20);
  printf("addr = %c\n", ((char *)addr)[4096]);
  ((char *)addr)[7000] = 'c';
  printf("a[0] = %c\n", ((char *)addr)[4096]);
  return 0;
}
