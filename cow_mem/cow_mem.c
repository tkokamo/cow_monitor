/* mychardev.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mmdebug.h>
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
#include <linux/mutex.h>
#include <linux/rbtree_augmented.h>
#include <asm-generic/atomic-long.h>
#include <linux/preempt_mask.h>
#include <linux/task_work.h>
#include <linux/fsnotify.h>
#include <linux/eventpoll.h>
#include <uapi/asm-generic/fcntl.h>
#include <linux/ima.h>
#include <linux/stat.h>
#include <linux/hugetlb_inline.h>
#include <linux/cdev.h>
#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/sysfs.h>
#include <linux/preempt.h>
#include <linux/percpu-defs.h>
#include <linux/percpu_counter.h>
#include <linux/mount.h>
#include <linux/printk.h>
#include <linux/backing-dev.h>
#include <linux/kconfig.h>
#include <linux/interval_tree_generic.h>

#include "cow_mem.h"
#define DEVICE_NAME "cow_monitor" 

int sysctl_max_map_count = DEFAULT_MAX_MAP_COUNT;
struct kmem_cache *vm_area_cachep;
struct kmem_cache *policy_cache;
struct kmem_cache *filp_cachep;

extern struct file *shmem_file_setup(const char *name, loff_t size, unsigned long flags);

struct mnt_namespace {
  atomic_t                count;
  unsigned int            proc_inum;
  struct mount *  root;
  struct list_head        list;
  struct user_namespace   *user_ns;
  u64                     seq;    /* Sequence number to prevent loops */
  wait_queue_head_t poll;
  u64 event;
};

struct mnt_pcp {
  int mnt_count;
  int mnt_writers;
};

struct mountpoint {
  struct hlist_node m_hash;
  struct dentry *m_dentry;
  struct hlist_head m_list; 
  int m_count;
};      

struct mount {
  struct hlist_node mnt_hash;
  struct mount *mnt_parent;
  struct dentry *mnt_mountpoint;
  struct vfsmount mnt;
  union {
    struct rcu_head mnt_rcu;
    struct llist_node mnt_llist;
  };
  struct mnt_pcp __percpu *mnt_pcp;
  struct list_head mnt_mounts;    /* list of children, anchored here */
  struct list_head mnt_child;     /* and going through their mnt_child */
  struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
  const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
  struct list_head mnt_list;
  struct list_head mnt_expire;    /* link in fs-specific expiry list */
  struct list_head mnt_share;     /* circular list of shared mounts */
  struct list_head mnt_slave_list;/* list of slave mounts */
  struct list_head mnt_slave;     /* slave list entry */
  struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
  struct mnt_namespace *mnt_ns;   /* containing namespace */
  struct mountpoint *mnt_mp;      /* where is it mounted */
  struct hlist_node mnt_mp_list;  /* list mounts with the same mountpoint */
  struct hlist_head mnt_fsnotify_marks;
  __u32 mnt_fsnotify_mask;
  int mnt_id;                     /* mount identifier */
  int mnt_group_id;               /* peer group identifier */
  int mnt_expiry_mark;            /* true if marked for expiry */
  struct hlist_head mnt_pins;
  struct path mnt_ex_mountpoint;
};
  

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

const struct vm_operations_struct generic_file_vm_ops = {
  .fault          = filemap_fault,
  .map_pages      = filemap_map_pages,
  .page_mkwrite   = filemap_page_mkwrite,
  .remap_pages    = generic_file_remap_pages,
};

#define shmem_vm_ops generic_file_vm_ops

int cow_shmem_zero_setup(struct vm_area_struct *vma)
{
  struct file *file;
  loff_t size = vma->vm_end - vma->vm_start;

  file = shmem_file_setup("dev/zero", size, vma->vm_flags);
  if (IS_ERR(file))
    return PTR_ERR(file);

  /*  if (vma->vm_file)
    fput(vma->vm_file); */
  vma->vm_file = file;
  vma->vm_ops = &shmem_vm_ops; //
  return 0;
}

static inline unsigned long vma_start_pgoff(struct vm_area_struct *v)
{
  return v->vm_pgoff;
}

static inline unsigned long vma_last_pgoff(struct vm_area_struct *v)
{
  return v->vm_pgoff + ((v->vm_end - v->vm_start) >> PAGE_SHIFT) - 1;
}

INTERVAL_TREE_DEFINE(struct vm_area_struct, shared.linear.rb,
                     unsigned long, shared.linear.rb_subtree_last,
                     vma_start_pgoff, vma_last_pgoff,, vma_interval_tree)

static void __vma_link_file(struct vm_area_struct *vma)
{
  struct file *file;

  file = vma->vm_file;
  if (file) {
    struct address_space *mapping = file->f_mapping;
        
    if (vma->vm_flags & VM_DENYWRITE)
      atomic_dec(&file_inode(file)->i_writecount);
    if (vma->vm_flags & VM_SHARED)
      atomic_inc(&mapping->i_mmap_writable);

    flush_dcache_mmap_lock(mapping);
    if (unlikely(vma->vm_flags & VM_NONLINEAR))
      vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
    else
      vma_interval_tree_insert(vma, &mapping->i_mmap);
    flush_dcache_mmap_unlock(mapping);
  }                               
}


void __vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		     struct vm_area_struct *prev, struct rb_node *rb_parent)
{
  struct vm_area_struct *next;

  vma->vm_prev = prev;
  if (prev) {
    next = prev->vm_next;
    prev->vm_next = vma;
  } else {
    mm->mmap = vma;
    if (rb_parent)
      next = rb_entry(rb_parent,
		      struct vm_area_struct, vm_rb);
    else
      next = NULL;
  }
  vma->vm_next = next;
  if (next)
    next->vm_prev = vma;
}


static long vma_compute_subtree_gap(struct vm_area_struct *vma)
{
  unsigned long max, subtree_gap;
  max = vma->vm_start;
  if (vma->vm_prev)
    max -= vma->vm_prev->vm_end;
  if (vma->vm_rb.rb_left) {
    subtree_gap = rb_entry(vma->vm_rb.rb_left,
			   struct vm_area_struct, vm_rb)->rb_subtree_gap;
    if (subtree_gap > max)
      max = subtree_gap;
  }               
  if (vma->vm_rb.rb_right) {
    subtree_gap = rb_entry(vma->vm_rb.rb_right,
			   struct vm_area_struct, vm_rb)->rb_subtree_gap;  
    if (subtree_gap > max)
      max = subtree_gap;
  }
  return max;
}

#define validate_mm_rb(root, ignore) do {} while(0)
#define validate_mm(mm) do {} while(0)

RB_DECLARE_CALLBACKS(static, vma_gap_callbacks, struct vm_area_struct, vm_rb, unsigned long, rb_subtree_gap, vma_compute_subtree_gap)

static void vma_gap_update(struct vm_area_struct *vma)
{       
  /*      
   * As it turns out, RB_DECLARE_CALLBACKS() already created a callback
   * function that does exacltly what we want.
   */
  vma_gap_callbacks_propagate(&vma->vm_rb, NULL);
}

static inline void vma_rb_insert(struct vm_area_struct *vma,
                                 struct rb_root *root)
{       
  /* All rb_subtree_gap values must be consistent prior to insertion */
  validate_mm_rb(root, NULL);

  rb_insert_augmented(&vma->vm_rb, root, &vma_gap_callbacks);
}

void __vma_link_rb(struct mm_struct *mm, struct vm_area_struct *vma,
		   struct rb_node **rb_link, struct rb_node *rb_parent)
{
  /* Update tracking information for the gap following the new vma. */
  if (vma->vm_next)
    vma_gap_update(vma->vm_next);
  else
    mm->highest_vm_end = vma->vm_end;
                
  /*
   * vma->vm_prev wasn't known when we followed the rbtree to find the
   * correct insertion point for that vma. As a result, we could not
   * update the vma vm_rb parents rb_subtree_gap values on the way down.
   * So, we first insert the vma with a zero rb_subtree_gap value
   * (to be consistent with what we did on the way down), and then
   * immediately update the gap to the correct value. Finally we
   * rebalance the rbtree after all augmented values have been set.
   */
  rb_link_node(&vma->vm_rb, rb_parent, rb_link);
  vma->rb_subtree_gap = 0;
  vma_gap_update(vma);
  vma_rb_insert(vma, &mm->mm_rb);
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	   struct vm_area_struct *prev, struct rb_node **rb_link,
	   struct rb_node *rb_parent)
{
  __vma_link_list(mm, vma, prev, rb_parent);
  __vma_link_rb(mm, vma, rb_link, rb_parent);
}


static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
		     struct vm_area_struct *prev, struct rb_node **rb_link,
		     struct rb_node *rb_parent)
{
  struct address_space *mapping = NULL;
        
  if (vma->vm_file) {
    mapping = vma->vm_file->f_mapping;
    mutex_lock(&mapping->i_mmap_mutex);
  }
                
  __vma_link(mm, vma, prev, rb_link, rb_parent);
  __vma_link_file(vma);

  if (mapping)
    mutex_unlock(&mapping->i_mmap_mutex);

  mm->map_count++;
  validate_mm(mm);
}       


static const char *gate_vma_name(struct vm_area_struct *vma)
{
  return "[vsyscall]";
}
static struct vm_operations_struct gate_vma_ops = {
  .name = gate_vma_name,
};
static struct vm_area_struct gate_vma = {
  .vm_start       = VSYSCALL_ADDR,
  .vm_end         = VSYSCALL_ADDR + PAGE_SIZE,
  .vm_page_prot   = PAGE_READONLY_EXEC,
  .vm_flags       = VM_READ | VM_EXEC,
  .vm_ops         = &gate_vma_ops,
};

struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
  if (!mm || mm->context.ia32_compat)
    return NULL;
  return &gate_vma;
}

void vm_stat_account(struct mm_struct *mm, unsigned long flags,
		     struct file *file, long pages)
{
        const unsigned long stack_flags
	  = VM_STACK_FLAGS & (VM_GROWSUP|VM_GROWSDOWN);

        mm->total_vm += pages;

        if (file) {
	  mm->shared_vm += pages;
	  if ((flags & (VM_EXEC|VM_WRITE)) == VM_EXEC)
	    mm->exec_vm += pages;
        } else if (flags & stack_flags)
	  mm->stack_vm += pages;
}


static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
  return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

#define pgprot_val(x)   ((x).pgprot)

int vma_wants_writenotify(struct vm_area_struct *vma)
{
  vm_flags_t vm_flags = vma->vm_flags;
        
  /* If it was private or non-writable, the write bit is already clear */
  if ((vm_flags & (VM_WRITE|VM_SHARED)) != ((VM_WRITE|VM_SHARED)))
    return 0;

  /* The backer wishes to know when pages are first written to? */
  if (vma->vm_ops && vma->vm_ops->page_mkwrite)
    return 1;

  /* The open routine did something to the protections that pgprot_modify
   * won't preserve? */
  if (pgprot_val(vma->vm_page_prot) !=
      pgprot_val(vm_pgprot_modify(vma->vm_page_prot, vm_flags)))
    return 0;

  /* Do we need to track softdirty? */
  if (IS_ENABLED(CONFIG_MEM_SOFT_DIRTY) && !(vm_flags & VM_SOFTDIRTY))
    return 1;
 
  /* Specialty mapping? */
  if (vm_flags & VM_PFNMAP)
    return 0;

  /* Can the mapping track the dirty pages? */
        return vma->vm_file && vma->vm_file->f_mapping &&
	  mapping_cap_account_dirty(vma->vm_file->f_mapping);
}

/* Update vma->vm_page_prot to reflect vma->vm_flags. */
void vma_set_page_prot(struct vm_area_struct *vma)
{                                               
  unsigned long vm_flags = vma->vm_flags;

  vma->vm_page_prot = vm_pgprot_modify(vma->vm_page_prot, vm_flags);
  if (vma_wants_writenotify(vma)) {
    vm_flags &= ~VM_SHARED;
    vma->vm_page_prot = vm_pgprot_modify(vma->vm_page_prot,
					 vm_flags);
  }       
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
    error = cow_shmem_zero_setup(vma);
    if (error)
      goto free_vma;
  }
  vma_link(mm, vma, prev, rb_link, rb_parent);

  //perf. is it necessary?

  //stat account
  vm_stat_account(mm, vm_flags, NULL, len >> PAGE_SHIFT);

  //
  if (vm_flags & VM_LOCKED) {
    if (!((vm_flags & VM_SPECIAL) || is_vm_hugetlb_page(vma) ||
	  vma == get_gate_vma(current->mm)))
      mm->locked_vm += (len >> PAGE_SHIFT);
    else
      vma->vm_flags &= ~VM_LOCKED;
  }

  vma->vm_flags |= VM_SOFTDIRTY;

  vma_set_page_prot(vma);

  return addr;
 free_vma:
  kmem_cache_free(vm_area_cachep, vma);
  
 unacct_error:  
  return error;
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
  filp_cachep = KMEM_CACHE(file, SLAB_PANIC);
  policy_cache = kmem_cache_create("numa_policy", sizeof(struct mempolicy), 0, SLAB_PANIC, NULL);
  return 0;
}

void cleanup_module(void)
{
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
  kmem_cache_destroy(vm_area_cachep);
  kmem_cache_destroy(policy_cache);
  kmem_cache_destroy(filp_cachep);
}

MODULE_LICENSE("GPL");
