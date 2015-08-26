/* ioctl.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "cow_monitor.h"

int main()
{
  int fd;
  int ret_val;
  struct cow_monitor cow;
  
  fd = open(DEVICE_FILE_NAME, 0);
  if (fd < 0) {
    printf("Can't open device file: %s\n", DEVICE_FILE_NAME);
    exit(1);
  }

  cow.pid = (pid_t)630;
  cow.addr = (void *)0x7f29aa7ed000;
  ret_val = ioctl(fd, IOCTL_COW_MONITOR, &cow);
  if (ret_val < 0) {
    printf("ioctl failed: %d\n", ret_val);
    exit(1);
  }

  close(fd);

  //  printf("[+] getuid() = %d\n", getuid());
  //execl("/bin/sh", "sh", NULL);
}
