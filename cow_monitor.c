/* mychardev.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

#include "cow_monitor.h"
#define DEVICE_NAME "cow_monitor"

static int device_open(struct inode *inode, struct file *file)
{
  try_module_get(THIS_MODULE);
  return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
  module_put(THIS_MODULE);
  return 0;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
  return -EINVAL;
}

static ssize_t device_write(struct file *filp, const char *buffer, size_t length, loff_t * offset)
{
  return -EINVAL;
}

long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  struct task_struct *ptr;
  struct mm_struct *target_mm, *current_mm;
  struct cow_monitor *cow;
  struct vm_area_struct *target_vm, *tmp;

  switch (ioctl_num) {
  case IOCTL_COW_MONITOR:
    ptr = &init_task;
    target_mm = NULL;
    current_mm = current->active_mm;
    cow = (struct cow_monitor *) ioctl_param;
    
    /*** get process task_struct from pid ***/
    while (ptr->tasks.next != NULL && list_entry(ptr->tasks.next, struct task_struct, tasks) != &init_task) {
      if (ptr->pid == cow->pid) {
	target_mm = ptr->active_mm;
      }
      ptr = list_entry(ptr->tasks.next, struct task_struct, tasks);
    }
    
    if (target_mm == NULL) {
      printk(KERN_ALERT "no process found with pid %d\n", (int) cow->pid);
      return -EINVAL;
    }
    
    
    // we got target process
    printk("we got target process\n");

    down_write(&target_mm->mmap_sem); //get semaphore
    down_write(&current_mm->mmap_sem);
    /*** check if the memory region specified by address is valid and has len length ***/
    
    target_vm = find_vma(target_mm, (unsigned long) cow->addr);
    if (target_vm == NULL || (unsigned long)cow->addr != target_vm->vm_start) {
      up_write(&target_mm->mmap_sem); //free semaphore
      printk(KERN_ALERT "no vm area found with addr == vm_start\n");
      return -EINVAL;
    }

    printk("we got target vm area\n");

    tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);



    
    up_write(&current_mm->mmap_sem);
    up_write(&target_mm->mmap_sem); //free semaphore    

    kmem_cache_free(vm_area_cachep, tmp);
    /***  ***/
    return 0;
  }
  return -EINVAL;
}

static struct file_operations fops = {
  .open = device_open,
  .release = device_release,
  .read = device_read,
  .write = device_write,
  .unlocked_ioctl = device_ioctl,
};

int init_module(void)
{
  int ret_val;
  ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
  if (ret_val < 0) {
    printk(KERN_ALERT "Registering char device failed with %d\n", ret_val);
    return ret_val;
  }
  printk(KERN_INFO "try 'sudo mknod %s c %d 0'\n", DEVICE_FILE_NAME, MAJOR_NUM);
  return 0;
}

void cleanup_module(void)
{
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
}

MODULE_LICENSE("GPL");
