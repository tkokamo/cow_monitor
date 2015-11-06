/* cow_monitor.h */
#ifndef COWMONITOR_H
#define COWMONITOR_H

#include <linux/ioctl.h>

struct cow_monitor {
  pid_t pid;
  void *addr;
  unsigned long len;
};

#define MAJOR_NUM 200
#define DEVICE_FILE_NAME "cow_mem"
#define IOCTL_COW_MONITOR _IOW(MAJOR_NUM, 0, struct cow_monitor)
#endif
