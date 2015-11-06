/* mychardev.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/sysctl.h>
#include <linux/security.h>
#include <linux/rbtree.h>
#include <linux/mempolicy.h>
#include <linux/err.h>
#include <linux/rcupdate.h>
#include <linux/nodemask.h>
#include <linux/compiler.h>
#include <linux/capability.h>
#include <linux/cpumask.h>
#include <linux/cgroup.h>
#include <linux/rmap.h>
#include <linux/rbtree.h>
//#include <linux/autoconf.h>
#include <uapi/linux/capability.h>


#include "cow_mem.h"
#define DEVICE_NAME "cow_monitor" 
int sysctl_max_map_count = DEFAULT_MAX_MAP_COUNT;
struct kmem_cache *vm_area_cachep;
struct kmem_cache *policy_cache;

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

//------------------------------------------
// Functions for dup mempolicy
// 
//------------------------------------------
struct fmeter {
  int cnt;                /* unprocessed events count */
  int val;                /* most recent output value */
  time_t time;            /* clock (secs) when val computed */
  spinlock_t lock;        /* guards read or write of above */
};      

struct cpuset {
  struct cgroup_subsys_state css;

  unsigned long flags;            /* "unsigned long" so bitops work */

  /* user-configured CPUs and Memory Nodes allow to tasks */
  cpumask_var_t cpus_allowed;
  nodemask_t mems_allowed;

  /* effective CPUs and Memory Nodes allow to tasks */
  cpumask_var_t effective_cpus;
  nodemask_t effective_mems;
  nodemask_t old_mems_allowed;

  struct fmeter fmeter;           /* memory_pressure filter */

  /*
   * Tasks are being attached to this cpuset.  Used to prevent
   * zeroing cpus/mems_allowed between ->can_attach() and ->attach().
   */
  int attach_in_progress;

  /* partition number for rebuild_sched_domains() */
  int pn;

  /* for custom sched domain */
  int relax_domain_level;
};
/*
int vma_dup_policy(struct vm_area_struct *src, struct vm_area_struct *dst)
{
  struct mempolicy *pol = mpol_dup(vma_policy(src));

  if (IS_ERR(pol))
    return PTR_ERR(pol);
  dst->vm_policy = pol;
  return 0; 
  }*/
//------------------------------------------
// Functions for dup mempolicy
// 
//------------------------------------------

//------------------------------------------
// Functions for copy pages
// 
//------------------------------------------

int copy_vm_pages(struct vm_area_struct *dst_vm, struct vm_area_struct *src_vm)
{
  
}

//------------------------------------------
// Functions for copy pages
// 
//------------------------------------------

static int find_vma_links(struct mm_struct *mm, unsigned long addr,
			  unsigned long end, struct vm_area_struct **pprev,
			  struct rb_node ***rb_link, struct rb_node **rb_parent)
{
  struct rb_node **__rb_link, *__rb_parent, *rb_prev;
        
  __rb_link = &mm->mm_rb.rb_node;
  rb_prev = __rb_parent = NULL;

  while (*__rb_link) {
    struct vm_area_struct *vma_tmp;
                
    __rb_parent = *__rb_link;
    vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

    if (vma_tmp->vm_end > addr) {
      /* Fail if an existing vma overlaps the area */
      if (vma_tmp->vm_start < end)
	return -ENOMEM;
      __rb_link = &__rb_parent->rb_left;
    } else {
      rb_prev = __rb_parent;
      __rb_link = &__rb_parent->rb_right;
    }
  }

  *pprev = NULL;
  if (rb_prev)
    *pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
  *rb_link = __rb_link;
  *rb_parent = __rb_parent;
  return 0;
}


static inline unsigned long 
calc_mmap_flag_bits(unsigned long flags)
{
  return _calc_vm_trans(flags, VM_GROWSDOWN, MAP_GROWSDOWN) | 
    _calc_vm_trans(flags, VM_DENYWRITE, MAP_DENYWRITE) |
    _calc_vm_trans(flags, VM_LOCKED, MAP_LOCKED);
}

static inline unsigned long
calc_mmap_prot_bits(unsigned long prot)
{
  return _calc_vm_trans(prot, VM_READ, PROT_READ) |
    _calc_vm_trans(prot, VM_WRITE, PROT_WRITE) |
    _calc_vm_trans(prot, VM_EXEC, PROT_EXEC);
}
  

static inline unsigned long cow_round_hint_to_min(unsigned long hint)
{
  hint &= PAGE_MASK;
  if (((void *)hint != NULL) &&
      (hint < CONFIG_DEFAULT_MMAP_MIN_ADDR))
    return PAGE_ALIGN(CONFIG_DEFAULT_MMAP_MIN_ADDR);
  return hint;
}

static inline int cow_mlock_future_check(struct mm_struct *mm,
                                     unsigned long flags,
                                     unsigned long len)
{
  unsigned long locked, lock_limit;

  /*  mlock MCL_FUTURE? */
  if (flags & VM_LOCKED) {
    locked = len >> PAGE_SHIFT;
    locked += mm->locked_vm;
    lock_limit = rlimit(RLIMIT_MEMLOCK);
    lock_limit >>= PAGE_SHIFT;      
    if (locked > lock_limit && !capable(CAP_IPC_LOCK))
      return -EAGAIN;
  }
  return 0;
}


unsigned long cow_mmap_region(unsigned long addr, unsigned long len, vm_flags_t vm_flags, unsigned long pgoff)
{
  /*

  */
  struct mm_struct *mm = current->mm;
  struct vm_area_struct *vma, *prev;
  int error;
  struct rb_node **rb_link, *rb_parent;
  unsigned long charged = 0;
  
  // omit the may_expand_vm section because vm_flags & MAP_FIXED will be 0
  
  error = -ENOMEM;
  find_vma_links(mm, addr, addr + len, &prev, &rb_link, &rb_parent);

  // what is accountable_mapping
  //
  //

  // no vma merge

  vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
  if (!vma) {
    error = -ENOMEM;
    goto unacct_error;
  }

  vma->vm_mm = mm;
  vma->vm_start = addr;
  vma->vm_end = addr + len;
  vma->vm_flags = vm_flags;
  vma->vm_page_prot = vm_get_page_prot(vm_flags);
  vma->vm_pgoff = pgoff;
  INIT_LIST_HEAD(&vma->anon_vma_chain);

  if (vm_flags & VM_SHARED) {
    ;
  }
  

 unacct_error:  
  return 100;
}

unsigned long cow_do_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long vm_flags, unsigned long pgoff)
{
  //  unsigned long vm_flags;

  if (!len) {
    printk(KERN_ALERT "invalid parameter\n");
    return -EINVAL;
  }
 
  if (!(flags & MAP_FIXED))
    addr = cow_round_hint_to_min(addr);

  len = PAGE_ALIGN(len);
  if (!len) {
    printk(KERN_ALERT "length overflowed\n");
    return -ENOMEM;
  }
  
  if (current->mm->map_count > sysctl_max_map_count) {
    printk(KERN_ALERT "there are already too many mappings\n");
    return -ENOMEM;    
  }
    

  addr = get_unmapped_area(NULL, addr, len, 0, flags);
  if (addr & ~PAGE_MASK)
    return addr;
  
  if (flags & MAP_LOCKED)
    if (!can_do_mlock())
      return -EPERM;

  if (cow_mlock_future_check(current->active_mm, vm_flags, len))
    return -EAGAIN;
  
  addr = cow_mmap_region(addr, len, vm_flags, pgoff);
  /*if (!IS_ERR_VALUE(addr) &&
      ((vm_flags & VM_LOCKED) ||
       (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
       *populate = len;*/
  printk("Finally, we come here\n");
  return addr;
}


long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  struct task_struct *ptr;
  struct mm_struct *target_mm, *current_mm;
  struct cow_monitor *cow;
  struct vm_area_struct *target_vm, *tmp, *prev, **pprev;
  struct rb_node **rb_link, *rb_parent;
  unsigned long addr;
  unsigned long flags, prot;
  long retval;

  retval = -EINVAL;
  switch (ioctl_num) {
  case IOCTL_COW_MONITOR: 
    ptr = &init_task;
    target_mm = NULL;
    current_mm = current->active_mm;
    tmp = NULL;
    cow = (struct cow_monitor *) ioctl_param;
    
    /*** get process task_struct from pid ***/
    do {
      if (ptr->pid == cow->pid) {
	target_mm = ptr->active_mm;
	break;
      }
    } while (ptr->tasks.next != NULL && list_entry(ptr->tasks.next, struct task_struct, tasks) !=  (ptr = list_entry(ptr->tasks.next, struct task_struct, tasks)), &init_task);
    
    if (target_mm == NULL) {
      printk(KERN_ALERT "no process found with pid %d\n", (int) cow->pid);
      return -EINVAL;
    }
        
    // we got target process
    printk("we got target process\n");

    // try to get semaphore 
    down_write(&target_mm->mmap_sem); 
    if (target_mm != current_mm) down_write(&current_mm->mmap_sem);
    
    /*** check if the memory region specified by address is valid and has len length ***/
    target_vm = find_vma(target_mm, (unsigned long) cow->addr);
    if (target_vm == NULL || (unsigned long)cow->addr != target_vm->vm_start) {
      printk(KERN_ALERT "no vm area found with addr == vm_start\n");
      goto free_out;
    }
    
    printk("we got target vm area\n");

    /*** check if current task can have another memory map ***/
    if (current_mm->map_count > sysctl_max_map_count) {
      printk(KERN_ALERT "no more region can be mapped to this process\n");
      goto free_out;
    }

    flags = calc_mmap_flag_bits(target_vm->vm_flags); // calc MAP_XXX => VM_XXX flag for get_unmapped_area
    prot = calc_mmap_prot_bits(target_vm->vm_flags);


    // Here, we try mmap a region which has the same flag as target vm
    ////////////////////////////////
    addr = cow_do_mmap_pgoff(0, cow->len, prot, flags, target_vm->vm_flags, 0);
    printk("addr is %p\n", addr);
  }
  retval = 0;
 free_out:
  if (target_mm != current_mm) up_write(&current_mm->mmap_sem);
  up_write(&target_mm->mmap_sem);
  return retval;
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

  vm_area_cachep = KMEM_CACHE(vm_area_struct, SLAB_PANIC);
  policy_cache = kmem_cache_create("numa_policy", sizeof(struct mempolicy), 0, SLAB_PANIC, NULL);
  return 0;
}

void cleanup_module(void)
{
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
  kmem_cache_destroy(vm_area_cachep);
  kmem_cache_destroy(policy_cache);
}

MODULE_LICENSE("GPL");
