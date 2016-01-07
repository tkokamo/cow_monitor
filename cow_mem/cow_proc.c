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

int main(int argc, char **argv)
{

  void *ret_val;
  char *p;
  int pid = atoi(argv[1]);
  void *addr = (void *) atoll(argv[2]);
  printf("%d %p\n", pid, addr);
 
  ret_val = cow_mem(pid, addr, 1000000000);
  
  //  ((char *)ret_val)[0] = 'a';
  //printf("ret_val = %c\n", ((char *)ret_val)[0]);
  printf("ret = %p\n", ret_val);
  p = ret_val;
  
  printf("p[0] = %c\n", p[4096]);
  //  sleep(20);
  p[4096] = 'c';
  printf("p[0] = %c\n", p[4096]);
  printf("p[0] = %c\n", p[4096* (1000000000/4096 - 10)]);



  //  printf("[+] getuid() = %d\n", getuid());
  //execl("/bin/sh", "sh", NULL);
}
