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
  int pipefd[2];
  
  pid_t ppid = getpid();
  if (pipe(pipefd) < 0) {
    perror("pipe");
    exit(-1);
  }

  pid_t pid = fork();
  
  if (pid < 0) {
    perror("fork");
    exit(-1);
  } else if(pid > 0) {
    //parent process
    close(pipefd[0]);
    addr = mmap(NULL, 1000000000, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    ((char *)addr)[7000] = 'a';
    ((char *)addr)[1000000] = 'a';
    ((char *)addr)[900000] = 'a';
    ((char *)addr)[0] = 'a';
    ((char *)addr)[100000000] = 'a';
    printf("addr = %c\n", ((char *)addr)[7000]);
    unsigned long long ia[1];
    ia[0] = (unsigned long long)addr;
    write(pipefd[1], ia, sizeof ia);
    close(pipefd[1]);
    sleep(5);
    printf("addr = %c\n", ((char *)addr)[7000]);
  } else {

    close(pipefd[1]);
    sleep(1);
    unsigned long long buf[10];
    read(pipefd[0], buf, sizeof buf);
    addr = buf[0];

    ret_val = cow_mem(ppid, addr, 1000000000);
    printf("addr = %p, ret = %p\n", addr, ret_val);
  
    //  ((char *)ret_val)[0] = 'a';
    //printf("ret_val = %c\n", ((char *)ret_val)[0]);

    //    ((char *)addr)[7000] = 'b';
    p = ret_val;
    printf("p[0] = %c\n", p[7000]);

    //  sleep(20);
    p[7000] = 'c';
    printf("p[0] = %c\n", p[7000]);
    close(pipefd[0]);
  }

  return 0;
  //  printf("[+] getuid() = %d\n", getuid());
  //execl("/bin/sh", "sh", NULL);
}
