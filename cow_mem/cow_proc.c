/* ioctl.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include "cow_mem.h"

struct list_head {
  struct list_head *next, *prev;
};

void hexdump(void *address, int byte)
{
  int i = 0;
  unsigned char *c;
  for (i; i < byte; i++) {
    c = (unsigned char *)address+i;
    printf("%x%x ", (*c & 0xf0) >> 4, *c & 0x0f);
    if (i % 64 == 63) printf("\n");
  }
  printf("\n");
}

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
  unsigned char *p;
  int pid = atoi(argv[1]);
  void *addr = (void *) atoll(argv[2]);
  unsigned long i;
  unsigned long offset;
  void *ptr;
  void *save;
  printf("%d %p\n", pid, addr);
 
  ret_val = cow_mem(pid, addr, 1000000000);
  save = mmap(NULL, 1073741824, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  //  ((char *)ret_val)[0] = 'a';
  //printf("ret_val = %c\n", ((char *)ret_val)[0]);
 
  printf("ret = %p\n", ret_val);
  p = ret_val;
  //  memcpy(save, p, 1073741824);

  offset = 0x1c15480;
  ptr = (unsigned char *)((struct list_head *)(p+offset+0x270))->next-0x270;                                        
  printf("init->next = %p\n", ptr);                                       
  
  do {
    printf("ID: %d NAME:%s\n", (pid_t)*(unsigned char *)(p+offset+0x2e4), (char *)(p+offset+0x4a8));
    offset = (((unsigned long long)(((struct list_head *)(p+offset+0x270))->next)) & 0x7fffffff) - 0x270;
    //    printf("%llx %llx\n", (unsigned long long)((struct list_head *)(p+offset+0x270))->next - 0x270, offset);     
  } while ((((unsigned long long)((struct list_head *)(p+offset+0x270))->next - 0x270) & 0x7fffffff) != 0x1c15480);
  for (i = 0; i < 1073741824; i++) {
    ((unsigned char*)p)[i] = ((unsigned char *)save)[i];
  }
  
  
  /*for (i = 0; i < 1000; i++) {
    printf("%x:", i);
    hexdump(p+offset+i,1);
    }*/

  sleep(30);
  for (i = 0; i < 1073741824; i++) {
    if (((unsigned char*)p)[i] != ((unsigned char *)save)[i])
      printf("memory content changed!!! %ld\n", i);
  }
  printf("memory content check finished\n");
  /*  offset = 0x1c15480;
  do {
    printf("ID: %d NAME:%s\n", (pid_t)*(unsigned char *)(p+offset+0x2e4), (char *)(p+offset+0x4a8));
    offset = (((unsigned long long)(((struct list_head *)(p+offset+0x270))->next)) & 0x7fffffff) - 0x270;
    //    printf("%llx %llx\n", (unsigned long long)((struct list_head *)(p+offset+0x270))->next - 0x270, offset);     
    } while ((((unsigned long long)((struct list_head *)(p+offset+0x270))->next - 0x270) & 0x7fffffff) != 0x1c15480);*/
  p[4096] = 'c';
  printf("p[0] = %c\n", p[10000]);
  printf("%lld\n", 4096*((unsigned long long)(1000000000/4096 - 100)));
  printf("p[...] = %c\n", p[4096*200000]);
  


  //  printf("[+] getuid() = %d\n", getuid());
  //execl("/bin/sh", "sh", NULL);
}
