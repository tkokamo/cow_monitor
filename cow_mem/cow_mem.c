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
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <asm-generic/mm_hooks.h>
#include "cow_mem.h"
#define DEVICE_NAME "cow_monitor" 

int sysctl_max_map_count = DEFAULT_MAX_MAP_COUNT;
struct kmem_cache *vm_area_cachep;
struct kmem_cache *policy_cache;
struct kmem_cache *filp_cachep;
static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;
//static inline unsigned char swap_count(unsigned char ent)
//{
//  return ent & ~SWAP_HAS_CACHE;   /* may include SWAP_HAS_CONT flag */
//}

extern struct file *shmem_file_setup(const char *name, loff_t size, unsigned long flags);
extern inline unsigned long
copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
	     pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
	     unsigned long addr, int *rss);
extern int add_swap_count_continuation(swp_entry_t entry, gfp_t gfp_mask);
//extern inline void arch_dup_mmap(struct mm_struct *oldmm,struct mm_struc:qt *mm);
extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start, unsigned long end, unsigned long vmflag);
#define TLB_FLUSH_ALL -1UL
#define flush_tlb_mm(mm)        flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL)


//extern spinlock_t mmlist_lock;

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

unsigned long cow_mmap_region(unsigned long addr, unsigned long len, vm_flags_t vm_flags, unsigned long pgoff, struct vm_area_struct **dst_vm_p)
{
  /*

  */
  struct mm_struct *mm = current->mm;
  struct vm_area_struct *vma, *prev;
  int error;
  struct rb_node **rb_link, *rb_parent;
  //unsigned long charged = 0;
  
  // omit the may_expand_vm section because vm_flags & MAP_FIXED will be 0
  
  error = -ENOMEM;
  find_vma_links(mm, addr, addr + len, &prev, &rb_link, &rb_parent);

  // what is accountable_mapping
  //
  //

  // no vma merge

  vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
  *dst_vm_p = vma;
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
  if (vma->vm_file)
    printk("vm_file is not null!\n");

  return addr;
 free_vma:
  *dst_vm_p = NULL;
  kmem_cache_free(vm_area_cachep, vma);
  
 unacct_error:  
  return error;
}

unsigned long cow_do_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long vm_flags, unsigned long pgoff, struct vm_area_struct **dst_vm_p)
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
  
  addr = cow_mmap_region(addr, len, vm_flags, pgoff, dst_vm_p);
  /*if (!IS_ERR_VALUE(addr) &&
      ((vm_flags & VM_LOCKED) ||
       (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
       *populate = len;*/
  printk("Finally, we come here\n");
  return addr;
}

/*
static inline struct cpuset *css_cs(struct cgroup_subsys_state *css)
{
  return css ? container_of(css, struct cpuset, css) : NULL;
}

static inline struct cpuset *task_cs(struct task_struct *task)
{
  return css_cs(task_css(task, cpuset_cgrp_id));
}

int current_cpuset_is_being_rebound(void)
{
  int ret;

  rcu_read_lock();
  ret = task_cs(current) == NULL;
  rcu_read_unlock();

  return ret;
}



nodemask_t cpuset_mems_allowed(struct task_struct *tsk)
{
  nodemask_t mask;

  mutex_lock(&callback_mutex);
  rcu_read_lock();
  guarantee_online_mems(task_cs(tsk), &mask);
  rcu_read_unlock();
  mutex_unlock(&callback_mutex);

  return mask;
}

struct mempolicy *__mpol_dup(struct mempolicy *old)
{               
  struct mempolicy *new = kmem_cache_alloc(policy_cache, GFP_KERNEL);

  if (!new)
    return ERR_PTR(-ENOMEM);
 
 
  if (old == current->mempolicy) {
    task_lock(current);
    *new = *old;
    task_unlock(current);
  } else
    *new = *old;

  if (current_cpuset_is_being_rebound()) {
    nodemask_t mems = cpuset_mems_allowed(current);
    if (new->flags & MPOL_F_REBINDING)
      mpol_rebind_policy(new, &mems, MPOL_REBIND_STEP2);
    else
      mpol_rebind_policy(new, &mems, MPOL_REBIND_ONCE);
  }
  atomic_set(&new->refcnt, 1);
  return new;
}

int vma_dup_policy(struct vm_area_struct *src, struct vm_area_struct *dst)
{
  struct mempolicy *pol = mpol_dup(vma_policy(src));

  if (IS_ERR(pol))
    return PTR_ERR(pol);
  dst->vm_policy = pol;
  return 0;
}
*/
//
// Level 2 from anon_vma_fork
//
static inline unsigned long avc_start_pgoff(struct anon_vma_chain *avc)
{
  return vma_start_pgoff(avc->vma);
}

static inline unsigned long avc_last_pgoff(struct anon_vma_chain *avc)
{
  return vma_last_pgoff(avc->vma);
}

INTERVAL_TREE_DEFINE(struct anon_vma_chain, rb, unsigned long, rb_subtree_last,
                     avc_start_pgoff, avc_last_pgoff,
                     static inline, __anon_vma_interval_tree)

void anon_vma_interval_tree_insert(struct anon_vma_chain *node,
                                   struct rb_root *root)
{
  __anon_vma_interval_tree_insert(node, root);
}

void anon_vma_interval_tree_remove(struct anon_vma_chain *node,
                                   struct rb_root *root)
{   
  __anon_vma_interval_tree_remove(node, root);
}

static void anon_vma_chain_free(struct anon_vma_chain *anon_vma_chain)
{                    
  kmem_cache_free(anon_vma_chain_cachep, anon_vma_chain);
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
  VM_BUG_ON(atomic_read(&anon_vma->refcount));

  /*
   * Synchronize against page_lock_anon_vma_read() such that
   * we can safely hold the lock without the anon_vma getting
   * freed.
   *
   * Relies on the full mb implied by the atomic_dec_and_test() from
   * put_anon_vma() against the acquire barrier implied by
   * down_read_trylock() from page_lock_anon_vma_read(). This orders:
   *
   * page_lock_anon_vma_read()    VS      put_anon_vma()
   *   down_read_trylock()                  atomic_dec_and_test()
   *   LOCK                                 MB
   *   atomic_read()                        rwsem_is_locked()
   *
   * LOCK should suffice since the actual taking of the lock must
   * happen _before_ what follows.
   */
  might_sleep();
  if (rwsem_is_locked(&anon_vma->root->rwsem)) {
    anon_vma_lock_write(anon_vma);
    anon_vma_unlock_write(anon_vma);
  }

  kmem_cache_free(anon_vma_cachep, anon_vma);
}

void __put_anon_vma(struct anon_vma *anon_vma)
{
  struct anon_vma *root = anon_vma->root;
                
  anon_vma_free(anon_vma);
  if (root != anon_vma && atomic_dec_and_test(&root->refcount))
    anon_vma_free(root);
}


//
// Level 1 from anon_vma_fork
//
static inline struct anon_vma_chain *anon_vma_chain_alloc(gfp_t gfp)
{
  return kmem_cache_alloc(anon_vma_chain_cachep, gfp);
}

static inline struct anon_vma *anon_vma_alloc(void)
{
  struct anon_vma *anon_vma;

  anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_KERNEL);
  if (anon_vma) {
    atomic_set(&anon_vma->refcount, 1);
    anon_vma->degree = 1;   /* Reference for first vma */
    anon_vma->parent = anon_vma;
    /*
     * Initialise the anon_vma root to point to itself. If called
     * from fork, the root will be reset to the parents anon_vma.
     */
    anon_vma->root = anon_vma;
  }

  return anon_vma;
}

static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
  struct anon_vma *new_root = anon_vma->root;
  if (new_root != root) {
    if (WARN_ON_ONCE(root))
      up_write(&root->rwsem);
    root = new_root;
    down_write(&root->rwsem);
  }
  return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
  if (root)
    up_write(&root->rwsem);
}

static void anon_vma_chain_link(struct vm_area_struct *vma,
                                struct anon_vma_chain *avc,
                                struct anon_vma *anon_vma)
{
  avc->vma = vma;
  avc->anon_vma = anon_vma;
  list_add(&avc->same_vma, &vma->anon_vma_chain);
  anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
}


void unlink_anon_vmas(struct vm_area_struct *vma)
{
  struct anon_vma_chain *avc, *next;
  struct anon_vma *root = NULL;

  /*
   * Unlink each anon_vma chained to the VMA.  This list is ordered
   * from newest to oldest, ensuring the root anon_vma gets freed last.
   */
  list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
    struct anon_vma *anon_vma = avc->anon_vma;

    root = lock_anon_vma_root(root, anon_vma);
    anon_vma_interval_tree_remove(avc, &anon_vma->rb_root);

    /*
     * Leave empty anon_vmas on the list - we'll need
     * to free them outside the lock.
     */
    if (RB_EMPTY_ROOT(&anon_vma->rb_root)) {
      anon_vma->parent->degree--;
      continue;
    }

    list_del(&avc->same_vma);
    anon_vma_chain_free(avc);
  }
  if (vma->anon_vma)
    vma->anon_vma->degree--;
  unlock_anon_vma_root(root);
  /*
   * Iterate the list once more, it now only contains empty and unlinked
   * anon_vmas, destroy them. Could not do before due to __put_anon_vma()
   * needing to write-acquire the anon_vma->root->rwsem.
   */
  list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
    struct anon_vma *anon_vma = avc->anon_vma;

    BUG_ON(anon_vma->degree);
    put_anon_vma(anon_vma);

    list_del(&avc->same_vma);
    anon_vma_chain_free(avc);
  }
}

int anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
  struct anon_vma_chain *avc, *pavc;
  struct anon_vma *root = NULL;

  list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
    struct anon_vma *anon_vma;

    avc = anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
    if (unlikely(!avc)) {
      unlock_anon_vma_root(root);
      root = NULL;
      avc = anon_vma_chain_alloc(GFP_KERNEL);
      if (!avc)
	goto enomem_failure;
    }
    anon_vma = pavc->anon_vma;
    root = lock_anon_vma_root(root, anon_vma);
    anon_vma_chain_link(dst, avc, anon_vma);

    /*
     * Reuse existing anon_vma if its degree lower than two,
     * that means it has no vma and only one anon_vma child.
     *
     * Do not chose parent anon_vma, otherwise first child
     * will always reuse it. Root anon_vma is never reused:
     * it has self-parent reference and at least one child.
     */
    if (!dst->anon_vma && anon_vma != src->anon_vma &&
	anon_vma->degree < 2)
      dst->anon_vma = anon_vma;
  }
  if (dst->anon_vma)
    dst->anon_vma->degree++;
  unlock_anon_vma_root(root);
  return 0;

 enomem_failure:
  /*
   * dst->anon_vma is dropped here otherwise its degree can be incorrectly
   * decremented in unlink_anon_vmas().
   * We can safely do this because callers of anon_vma_clone() don't care
   * about dst->anon_vma if anon_vma_clone() failed.
   */
  dst->anon_vma = NULL;
  unlink_anon_vmas(dst);
  return -ENOMEM;
}

//
// Level 0 from anon_vma_fork
//
int anon_vma_fork(struct vm_area_struct *vma, struct vm_area_struct *pvma)
{
  struct anon_vma_chain *avc;
  struct anon_vma *anon_vma;
  int error;

  /* Don't bother if the parent process has no anon_vma here. */
  if (!pvma->anon_vma)
    return 0;

  /* Drop inherited anon_vma, we'll reuse existing or allocate new. */
  printk(KERN_ALERT "vma->anon_vma\n");
  vma->anon_vma = NULL;

  /*
   * First, attach the new VMA to the parent VMA's anon_vmas,
   * so rmap can find non-COWed pages in child processes.
   */
  printk(KERN_ALERT "anon_vma_clone\n");
  error = anon_vma_clone(vma, pvma);
  if (error)
    return error;

  /* An existing anon_vma has been reused, all done then. */
  printk(KERN_ALERT "vma->anon_vma\n");
  if (vma->anon_vma)
    return 0;

  /* Then add our own anon_vma. */
  printk(KERN_ALERT "alloc\n");
  anon_vma = anon_vma_alloc();
  if (!anon_vma)
    goto out_error;
  printk(KERN_ALERT "chain_alloc\n");
  avc = anon_vma_chain_alloc(GFP_KERNEL);
  if (!avc)
    goto out_error_free_anon_vma;

  /*
   * The root anon_vma's spinlock is the lock actually used when we
   * lock any of the anon_vmas in this anon_vma tree.
   */
  printk(KERN_ALERT "vma->root\n");
  anon_vma->root = pvma->anon_vma->root;
  anon_vma->parent = pvma->anon_vma;
  /*
   * With refcounts, an anon_vma can stay around longer than the
   * process it belongs to. The root anon_vma needs to be pinned until
   * this anon_vma is freed, because the lock lives in the root.
   */
  get_anon_vma(anon_vma->root);
  /* Mark this anon_vma as the one where our new (COWed) pages go. */
  vma->anon_vma = anon_vma;
  anon_vma_lock_write(anon_vma);
  anon_vma_chain_link(vma, avc, anon_vma);
  anon_vma->parent->degree++;
  anon_vma_unlock_write(anon_vma);

  return 0;

 out_error_free_anon_vma:
  put_anon_vma(anon_vma);
 out_error:
  unlink_anon_vmas(vma);
  return -ENOMEM;
}

static inline bool is_cow_mapping(vm_flags_t flags)
{
  return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

void pgd_clear_bad(pgd_t *pgd)
{
  pgd_ERROR(*pgd);
  pgd_clear(pgd);
}

void pud_clear_bad(pud_t *pud)
{
  pud_ERROR(*pud);
  pud_clear(pud);
}

void pmd_clear_bad(pmd_t *pmd)
{
  pmd_ERROR(*pmd);
  pmd_clear(pmd);
}

struct pgtable_cache{
  unsigned int pgd_idx, pud_idx, pmd_idx;
  pgd_t *pgd_val;
  pud_t *pud_val;
  pmd_t *pmd_val;
  spinlock_t *locked_ptl;
};

/*
static int __swap_duplicate(swp_entry_t entry, unsigned char usage)
{
  struct swap_info_struct *p;
  unsigned long offset, type;
  unsigned char count;
  unsigned char has_cache;
  int err = -EINVAL; 

  if (non_swap_entry(entry))
    goto out;

  type = swp_type(entry); 
  if (type >= nr_swapfiles)
    goto bad_file;
  p = swap_info[type];
  offset = swp_offset(entry);

  spin_lock(&p->lock);
  if (unlikely(offset >= p->max))
    goto unlock_out;

  count = p->swap_map[offset];

  
  if (unlikely(swap_count(count) == SWAP_MAP_BAD)) {
    err = -ENOENT;
    goto unlock_out;
  }

  has_cache = count & SWAP_HAS_CACHE;
  count &= ~SWAP_HAS_CACHE;
  err = 0;

  if (usage == SWAP_HAS_CACHE) {

    if (!has_cache && count)
      has_cache = SWAP_HAS_CACHE;
    else if (has_cache)            
      err = -EEXIST;
    else                           
      err = -ENOENT;

  } else if (count || has_cache) {

    if ((count & ~COUNT_CONTINUED) < SWAP_MAP_MAX)
      count += usage;
    else if ((count & ~COUNT_CONTINUED) > SWAP_MAP_MAX)
      err = -EINVAL;
    else if (swap_count_continued(p, offset, count))
      count = COUNT_CONTINUED;
    else
      err = -ENOMEM;
  } else
    err = -ENOENT;                 

  p->swap_map[offset] = count | has_cache;

 unlock_out:
  spin_unlock(&p->lock);
 out:
  return err;

 bad_file:
  pr_err("swap_dup: %s%08lx\n", Bad_file, entry.val);
  goto out;
}


int swap_duplicate(swp_entry_t entry)
{
  int err = 0;

  while (!err && __swap_duplicate(entry, 1) == -ENOMEM)
    err = add_swap_count_continuation(entry, GFP_ATOMIC);
  return err;
}
*/

#define PGALLOC_USER_GFP 0
#define PGALLOC_GFP GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO

pgtable_t pte_alloc_one(struct mm_struct *mm, unsigned long address)
{       
  struct page *pte;

  pte = alloc_pages(PGALLOC_GFP | PGALLOC_USER_GFP, 0);
  if (!pte)
    return NULL;
  if (!pgtable_page_ctor(pte)) {
    __free_page(pte); 
    return NULL;
  }
  return pte;
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
                                struct page *pte)
{
  unsigned long pfn = page_to_pfn(pte);

  //  paravirt_alloc_pte(mm, pfn);
  set_pmd(pmd, __pmd(((pteval_t)pfn << PAGE_SHIFT) | _PAGE_TABLE));
} 

static inline void pte_free(struct mm_struct *mm, struct page *pte)
{
  pgtable_page_dtor(pte);
  __free_page(pte);
}


int __pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
                pmd_t *pmd, unsigned long address)
{
  spinlock_t *ptl;
  pgtable_t new = pte_alloc_one(mm, address);
  int wait_split_huge_page;
  if (!new)
    return -ENOMEM;

  /*
   * Ensure all pte setup (eg. pte page lock and page clearing) are
   * visible before the pte is made visible to other CPUs by being
   * put into page tables.
   * 
   * The other side of the story is the pointer chasing in the page
   * table walking code (when walking the page table without locking;
   * ie. most of the time). Fortunately, these data accesses consist
   * of a chain of data-dependent loads, meaning most CPUs (alpha
   * being the notable exception) will already guarantee loads are
   * seen in-order. See the alpha page table accessors for the
   * smp_read_barrier_depends() barriers in page table walking code.
   */
  smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */

  ptl = pmd_lock(mm, pmd);
  wait_split_huge_page = 0;
  if (likely(pmd_none(*pmd))) {   /* Has another populated it ? */
    atomic_long_inc(&mm->nr_ptes);
    pmd_populate(mm, pmd, new);
    new = NULL;
  } else if (unlikely(pmd_trans_splitting(*pmd)))
    wait_split_huge_page = 1;
  spin_unlock(ptl);
  if (new)
    pte_free(mm, new);
  if (wait_split_huge_page)
    wait_split_huge_page(vma->anon_vma, pmd);
  return 0;
}


static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
  struct page *page;
  page = alloc_pages(GFP_KERNEL | __GFP_REPEAT | __GFP_ZERO, 0);
  if (!page)
    return NULL;
  if (!pgtable_pmd_page_ctor(page)) {
    __free_pages(page, 0);
    return NULL;
  }
  return (pmd_t *)page_address(page);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
  BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
  pgtable_pmd_page_dtor(virt_to_page(pmd));
  free_page((unsigned long)pmd);
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
  //  paravirt_alloc_pmd(mm, __pa(pmd) >> PAGE_SHIFT);
  set_pud(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}

int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
  pmd_t *new = pmd_alloc_one(mm, address);
  if (!new)
    return -ENOMEM;

  smp_wmb(); /* See comment in __pte_alloc */ 

  spin_lock(&mm->page_table_lock);

  if (pud_present(*pud))          /* Another has populated it */
    pmd_free(mm, new);
  else
    pud_populate(mm, pud, new);
  spin_unlock(&mm->page_table_lock);
  return 0;
}



static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
  //  paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT); 
  set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
  return (pud_t *)get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{       
  BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
  free_page((unsigned long)pud);
}       


int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
  pud_t *new = pud_alloc_one(mm, address);
  if (!new)
    return -ENOMEM;

  smp_wmb(); /* See comment in __pte_alloc */

  spin_lock(&mm->page_table_lock);
  if (pgd_present(*pgd))          /* Another has populated it */
    pud_free(mm, new);
  else
    pgd_populate(mm, pgd, new);
  spin_unlock(&mm->page_table_lock);
  return 0; 
}


pte_t *get_pte_and_lock(struct mm_struct *mm, unsigned long addr, struct pgtable_cache *ptc)
{
  pgd_t *pgd_val;
  pud_t *pud_val;
  pmd_t *pmd_val;
  pte_t *pte_val;

  if (pgd_index(addr) != ptc->pgd_idx)
    goto pud_update;
  pgd_val = ptc->pgd_val;
  if (pud_index(addr) != ptc->pud_idx)
    goto pmd_update;
  pud_val = ptc->pud_val;
  if (pmd_index(addr) != ptc->pmd_idx)
    goto pte_update;
  pmd_val = ptc->pmd_val;
  pte_val = pte_offset_map(pmd_val, addr);
  return pte_val;

 pud_update:
  printk(KERN_ALERT "pud_update\n");
  pgd_val = pgd_offset(mm, addr);
  ptc->pgd_val = pgd_val;
  ptc->pgd_idx = pgd_index(addr);
  pud_val = pud_alloc(mm, pgd_val, addr);
 
 pmd_update:
  printk(KERN_ALERT "pmd_update\n");
  pud_val = pud_offset(pgd_val, addr);
  ptc->pud_val = pud_val;
  ptc->pud_idx = pud_index(addr);
  pmd_val = pmd_alloc(mm, pud_val, addr);
  
 pte_update:
  printk(KERN_ALERT "ptd_update\n");
  pmd_val = pmd_offset(pud_val, addr);
  ptc->pmd_val = pmd_val;
  ptc->pmd_idx = pmd_index(addr);
  if (ptc->locked_ptl != NULL) {
    spin_unlock(ptc->locked_ptl);
    ptc->locked_ptl = NULL;
  }
  pte_val = pte_alloc_map_lock(mm, pmd_val, addr, &(ptc->locked_ptl));

  printk(KERN_ALERT "1 dst pte \n");
  return pte_val;
}



static inline void init_rss_vec(int *rss)
{
  memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}

void sync_mm_rss(struct mm_struct *mm)
{
  int i;

  for (i = 0; i < NR_MM_COUNTERS; i++) {
    if (current->rss_stat.count[i]) {
      add_mm_counter(mm, i, current->rss_stat.count[i]);
      current->rss_stat.count[i] = 0;
    }              
  }
  current->rss_stat.events = 0;
}

static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
  int i;

  if (current->mm == mm)
    sync_mm_rss(mm);
  for (i = 0; i < NR_MM_COUNTERS; i++)
    if (rss[i])
      add_mm_counter(mm, i, rss[i]);
}


int copy_pte_pages(struct mm_struct *dst_mm, struct vm_area_struct *dst_vm, struct mm_struct *src_mm, struct vm_area_struct *src_vm, pmd_t *src_pmd, unsigned long addr, unsigned long end, unsigned long *i, struct pgtable_cache *ptc)
{
  pte_t *orig_src_pte, *orig_dst_pte;
  pte_t *src_pte, *dst_pte;
  spinlock_t *src_ptl, *dst_ptl;
  int progress = 0;
  int rss[NR_MM_COUNTERS];
  swp_entry_t entry = (swp_entry_t){0};
again:
  init_rss_vec(rss);
  printk(KERN_ALERT "start copy_pte_pages\n");
  dst_pte = get_pte_and_lock(dst_mm, dst_vm->vm_start + *i, ptc);
  if (!dst_pte)
    return -ENOMEM;
  src_pte = pte_offset_map(src_pmd, addr);
  src_ptl = pte_lockptr(src_mm, src_pmd);
  if (dst_mm != src_mm)
    spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
  orig_src_pte = src_pte;
  orig_dst_pte = dst_pte;
  arch_enter_lazy_mmu_mode();
  
  do {
    //    printk(KERN_ALERT "pte loop\n");
    dst_pte = get_pte_and_lock(dst_mm, dst_vm->vm_start + *i, ptc);
    if (!dst_pte) {
      printk(KERN_ALERT "dst_pte is null\n");
      return -ENOMEM;
    }
    if (progress >= 32) {
      progress = 0;
      if (need_resched() ||
	  spin_needbreak(src_ptl) || spin_needbreak(dst_ptl)) {
	printk(KERN_ALERT "break for resched\n");
	break;
      }
    }
    if (pte_none(*src_pte)) {
      progress++;
      continue;
    }
    entry.val = copy_one_pte(dst_mm, src_mm, dst_pte, src_pte,
			     src_vm, addr, rss);
    if (entry.val) {
      printk(KERN_ALERT "entry val\n");
      break;
    }
    progress += 8;
    printk("start:%lx, next:%lx, end:%lx, *i:%lx\n", addr, addr + PAGE_SIZE, end, *i);
  } while (src_pte++, *i += PAGE_SIZE, addr += PAGE_SIZE, addr != end);
  printk("out ot loop start:%lx, end:%lx, *i:%lx\n", addr, end, *i);
  if (  ptc->locked_ptl == NULL )
    printk(KERN_ALERT "ptc->locked_ptl is NULL\n");

  dst_ptl = ptc->locked_ptl;
  arch_leave_lazy_mmu_mode();
  if (dst_mm != src_mm)
    spin_unlock(src_ptl);
  pte_unmap(orig_src_pte);
  add_mm_rss_vec(dst_mm, rss);
  pte_unmap_unlock(orig_dst_pte, dst_ptl);
  ptc->locked_ptl = NULL;
  cond_resched();
  printk(KERN_ALERT "comming here\n");
  
  if (entry.val) {
    if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
      return -ENOMEM;
    progress = 0;
  }
  if (addr != end)
    goto again;
  return 0;
}


int copy_pmd_pages(struct mm_struct *dst_mm, struct vm_area_struct *dst_vm, struct mm_struct *src_mm, struct vm_area_struct *src_vm, pud_t *src_pud, unsigned long addr, unsigned long end, unsigned long *i, struct pgtable_cache *ptc)
{
  pmd_t *src_pmd;
  unsigned long next;
  unsigned long length;

  src_pmd = pmd_offset(src_pud, addr);
  length = end - addr;
  printk(KERN_ALERT "start:%lx,end:%lx,length:%lx\n", addr, end, length);
  do {     
    printk(KERN_ALERT "1 pmd loop\n");
    next = pmd_addr_end(addr, end);
   
    if (pmd_none_or_clear_bad(src_pmd)) {
      *i += ((unsigned long) 1 << PMD_SHIFT);
      continue;
    }
    if (copy_pte_pages(dst_mm, dst_vm, src_mm, src_vm, src_pmd, addr, next, i, ptc)) {
      return -ENOMEM;
    }
  } while (src_pmd++, addr = next, (addr != end) && (*i < length));
  return 0;
}



int copy_pud_pages(struct mm_struct *dst_mm, struct vm_area_struct *dst_vm, struct mm_struct *src_mm, struct vm_area_struct *src_vm, pgd_t *src_pgd, unsigned long addr, unsigned long end, unsigned long *i, struct pgtable_cache *ptc)
{
  pud_t *src_pud;
  unsigned long next, length;

  length = end - addr;
  src_pud = pud_offset(src_pgd, addr);
  do {
    next = pud_addr_end(addr, end);
    if (pud_none_or_clear_bad(src_pud)) {
      *i += ((unsigned long) 1 << PUD_SHIFT);
      continue;
    }
    if (copy_pmd_pages(dst_mm, dst_vm, src_mm, src_vm, src_pud, addr, next, i, ptc)) {
      return -ENOMEM;
    }
  } while (src_pud++, addr = next, (addr != end) && (*i < length));
}

int copy_vm_pages(struct mm_struct *dst_mm, struct vm_area_struct *dst_vm, struct mm_struct *src_mm, struct vm_area_struct *src_vm)
{
  pgd_t *src_pgd, *dst_pgd;
  unsigned long next;
  struct vm_area_struct *vma = src_vm;
  unsigned long src_start = src_vm->vm_start;
  unsigned long src_end = src_vm->vm_end;
  unsigned long dst_start = dst_vm->vm_start;
  unsigned long dst_end = dst_vm->vm_end;
  unsigned long addr, end;
  unsigned long i, length;
  bool is_cow;
  int ret;
  struct pgtable_cache ptc;
  

  if (!(vma->vm_flags & (VM_HUGETLB | VM_NONLINEAR |
			 VM_PFNMAP | VM_MIXEDMAP))) {
    if (!vma->anon_vma)
      return 0;
  }

  is_cow = is_cow_mapping(vma->vm_flags);
  if (is_cow)
    mmu_notifier_invalidate_range_start(src_mm, src_start,
					src_end);
  ret = 0;
  dst_pgd = pgd_offset(dst_mm, dst_start);
  src_pgd = pgd_offset(src_mm, src_start);
  addr = src_start;
  end = src_end;
  length = end - addr;
  i = 0;
  memset(&ptc, 0, sizeof(ptc));
  printk("src_start: %p, src_end: %p, dst_start: %p, dst_end: %p, length: %ld\n", (void *)src_start, (void *)src_end, (void *)dst_start, (void *)dst_end, length);
  do {
     next = pgd_addr_end(addr, end);
     if (pgd_none_or_clear_bad(src_pgd)) {
       i += ((unsigned long) 1 << PGDIR_SHIFT);
       continue;
     }
     if (copy_pud_pages(dst_mm, dst_vm, src_mm, src_vm, src_pgd, addr, next, &i, &ptc)) {
       return -ENOMEM;
     }
  } while (src_pgd++, addr = next, addr != end && i < length);


  if (is_cow)
    mmu_notifier_invalidate_range_end(src_mm, src_start, src_end);
  return ret;
}

unsigned long copyvma(struct mm_struct *dst_mm, struct vm_area_struct *dst_vm, struct mm_struct *src_mm, struct vm_area_struct *src_vm)
{
  int retval;
  //dup_vma_policy
  /*  retval = vma_dup_policy(src, dst);
  if (retval)
  goto fail_nomem_policy;*/
  if (anon_vma_fork(dst_vm, src_vm))
    goto fail_nomem_anon_vma_fork;
  
  //  retval = copy_pgtable(dst, src);
  retval = copy_vm_pages(dst_mm, dst_vm, src_mm, src_vm);
  if (dst_vm->vm_ops && dst_vm->vm_ops->open)
    dst_vm->vm_ops->open(dst_vm);


  if (retval)
    goto out;

  arch_dup_mmap(src_mm, dst_mm);
  retval = 0;
 out:
  flush_tlb_mm(src_mm);
  //  uprobe_end_dup_mmap();
  
  return retval;
  
  //retval = copy_vma_pages(dst_mm, dst_vm, src_mm, src_vm);

 fail_nomem_anon_vma_fork:
  //  mpol_put(vma_policy(dst));
 fail_nomem_policy:
 fail_nomem:
  retval = -ENOMEM; // free vma after return 
  //goto out;

}

void * device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  struct task_struct *ptr;
  struct mm_struct *target_mm, *current_mm;
  struct cow_monitor *cow;
  struct vm_area_struct *target_vm, *tmp, *prev, **pprev, *dst_vm;
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
    addr = cow_do_mmap_pgoff(0, cow->len, prot, flags, target_vm->vm_flags, 0, &dst_vm);
    printk("addr is %p\n", addr);

    // Here, try to copy page table from target_vm to what we made just above.
    copyvma(current_mm, dst_vm, target_mm, target_vm);

    if (target_mm != current_mm) up_write(&current_mm->mmap_sem);
    up_write(&target_mm->mmap_sem);

    cow->ret_addr = addr;
    return addr;
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

static void anon_vma_ctor(void *data)
{
  struct anon_vma *anon_vma = data;

  init_rwsem(&anon_vma->rwsem);
  atomic_set(&anon_vma->refcount, 0);
  anon_vma->rb_root = RB_ROOT;
}               
                
void __init anon_vma_init(void)
{
  anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
				      0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor);
  anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain, SLAB_PANIC);
}

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
  anon_vma_init();
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
