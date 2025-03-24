/* vim: set ts=8 sw=8 noexpandtab: */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/rbtree.h>
#include <linux/jhash.h>

#include "p2_part2.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ram Mude");
MODULE_DESCRIPTION("LKP25 P2");

extern unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);

/* HASH TABLE BEGIN */

/*
 * Let's make a hash table with 2^10 = 1024 bins
 */
#define MY_HASH_TABLE_BINS 10
#define MAX_STACK_TRACE 16
#define MAX_DEPTH 4
#define MAX_TOP_TASKS 20
static DEFINE_HASHTABLE(sched_htable, MY_HASH_TABLE_BINS);


#if (P2_PART2 == 1)
struct sched_hentry {
    unsigned long stack_entries[MAX_STACK_TRACE];
    unsigned int nr_entries;
    int count;
    struct hlist_node hash;
};

#elif (P2_PART2 == 2)
struct sched_hentry {
    unsigned long stack_entries[MAX_STACK_TRACE];
    unsigned int nr_entries;
    u64 total_exec_time;
    struct hlist_node hash;
};

#elif (P2_PART2 == 3)
static DEFINE_SPINLOCK(sched_rbtree_lock);

struct sched_rbentry {
    struct rb_node node;
    u64 exec_time;
    u32 stack_hash;
    unsigned long stack_entries[MAX_STACK_TRACE];
    unsigned int nr_entries;
};
#endif

static struct rb_root sched_rbtree = RB_ROOT;

static char symbol2[KSYM_NAME_LEN] = "pick_next_task_fair";
module_param_string(symbol2, symbol2, KSYM_NAME_LEN, 0644);

static struct kprobe kp2 = {
	.symbol_name	= symbol2,
};

#if (P2_PART2 == 1)
static void __kprobes handler_post2(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{

    unsigned long entries[MAX_STACK_TRACE];
	unsigned int nr_entries;
    struct sched_hentry *entry;
    struct hlist_node *tmp;
    unsigned long hash_key = 0;
    int i;

    if (user_mode(regs))
        nr_entries = stack_trace_save_user(entries, MAX_STACK_TRACE);
    else
        nr_entries = stack_trace_save(entries, MAX_STACK_TRACE, 0 );

    for (i = 0; i < nr_entries; i++)
        hash_key ^= entries[i];

    hash_for_each_possible_safe(sched_htable, entry, tmp, hash, hash_key) {
        if (entry->nr_entries == nr_entries &&
            !memcmp(entry->stack_entries, entries, nr_entries * sizeof(unsigned long))) {
            entry->count++;
            return;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return;

    memcpy(entry->stack_entries, entries, nr_entries * sizeof(unsigned long));
    entry->nr_entries = nr_entries;
    entry->count = 1;
    hash_add(sched_htable, &entry->hash, hash_key);
	return;
}

static int lkp25_p2_proc_show(struct seq_file *m, void *v)
{
	struct sched_hentry *entry;
    int bkt, i;

    seq_puts(m, "Stack Trace\tScheduling Count\n");
    
    hash_for_each(sched_htable, bkt, entry, hash) {
        for (i = 0; i < entry->nr_entries; i++)
            seq_printf(m, "%pS\n", (void *)entry->stack_entries[i]);
        seq_printf(m, "Count: %d\n\n", entry->count);
    }
    return 0;
}

#elif (P2_PART2 == 2)
static struct task_struct *prev_task = NULL;
static u64 prev_timestamp = 0;

static void __kprobes handler_post2(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct task_struct *curr = (struct task_struct *)regs->si;
    if (!curr) return;

    unsigned long entries[MAX_STACK_TRACE];
	unsigned int nr_entries;
    struct sched_hentry *entry;
    struct hlist_node *tmp;
    unsigned long hash_key = 0;
    int i;

    u64 now = ktime_get_ns();
    if (prev_task && prev_timestamp){
        u64 elapsed = now - prev_timestamp;
    
        if (user_mode(regs))
            nr_entries = stack_trace_save_user(entries, MAX_STACK_TRACE);
        else
            nr_entries = stack_trace_save(entries, MAX_STACK_TRACE, 0 );

        for (i = 0; i < nr_entries; i++)
            hash_key ^= entries[i];

        hash_for_each_possible_safe(sched_htable, entry, tmp, hash, hash_key) {
            if (entry->nr_entries == nr_entries &&
                !memcmp(entry->stack_entries, entries, nr_entries * sizeof(unsigned long))) {
                entry->total_exec_time += elapsed;
                goto update_prev;
            }
        }

        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            return;

        memcpy(entry->stack_entries, entries, nr_entries * sizeof(unsigned long));
        entry->nr_entries = nr_entries;
        entry->total_exec_time = elapsed;
        hash_add(sched_htable, &entry->hash, hash_key);
    }
update_prev:
    prev_task = curr;
    prev_timestamp = now;
	return;
}

static int lkp25_p2_proc_show(struct seq_file *m, void *v)
{
	struct sched_hentry *entry;
    int bkt, i;

    seq_printf(m, "Stack Trace\tCumulative CPU Time (ns)\n");
    
    hash_for_each(sched_htable, bkt, entry, hash) {
        for (i = 0; i < entry->nr_entries; i++){
            seq_printf(m, "%pS\n", (void *)entry->stack_entries[i]);
        }
        seq_printf(m, "Total Time: %llu ns\n\n", entry->total_exec_time);
    }
    return 0;
}

#elif (P2_PART2 == 3)

static struct task_struct *prev_task = NULL;
static u64 prev_timestamp = 0;

static struct sched_rbentry *rbtree_lookup(unsigned int nr_entries, unsigned long *entries) {
    struct rb_node *node = sched_rbtree.rb_node;

    // while (node) {
    //     struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
    //     int cmp = memcmp(entry->stack_entries, entries, nr_entries * sizeof(unsigned long));

    //     if (entry->nr_entries == nr_entries && cmp == 0) {
    //         return entry;
    //     }

    //     if (cmp < 0)
    //         node = node->rb_right;
    //     else
    //         node = node->rb_left;
    // }

    spin_lock(&sched_rbtree_lock);

    for (node = rb_first(&sched_rbtree); node; node= rb_next(node)){
        struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
        if (entry->nr_entries == nr_entries && !memcmp(entry->stack_entries, entries, nr_entries * sizeof(unsigned long))){
            return entry;
        }
    }
    spin_unlock(&sched_rbtree_lock);
    return NULL;
}

static void rbtree_insert(struct sched_rbentry *new_entry) {
    struct rb_node **link = &sched_rbtree.rb_node, *parent = NULL;

    spin_lock(&sched_rbtree_lock);
    while (*link) {
        struct sched_rbentry *entry = container_of(*link, struct sched_rbentry, node);
        parent = *link;

        if (new_entry->exec_time < entry->exec_time)
            link = &(*link)->rb_left;
        else if (new_entry->exec_time > entry->exec_time)
            link = &(*link)->rb_right;
        else if (new_entry->stack_hash < entry->stack_hash)
            link = &(*link)->rb_left;
        else if (new_entry->stack_hash > entry->stack_hash)
            link = &(*link)->rb_right;
        else {
            spin_unlock(&sched_rbtree_lock);
            return; // Duplicate entry, do not insert
        }
    }

    rb_link_node(&new_entry->node, parent, link);
    rb_insert_color(&new_entry->node, &sched_rbtree);
    spin_unlock(&sched_rbtree_lock);
    return;
}

static void rbtree_remove(struct sched_rbentry *entry) {
    spin_lock(&sched_rbtree_lock);
    rb_erase(&entry->node, &sched_rbtree);
    spin_unlock(&sched_rbtree_lock);
    kfree(entry);
    return;
}

static void __kprobes handler_post2(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct task_struct *curr = (struct task_struct *)regs->si;
    if (!curr){ 
        return;
    }

    unsigned long entries[MAX_STACK_TRACE];
	unsigned int nr_entries;

    u64 now = ktime_get_ns();
    if (prev_task && prev_timestamp){
        u64 elapsed = now - prev_timestamp;
    
        if (user_mode(regs)){
            nr_entries = stack_trace_save_user(entries, MAX_STACK_TRACE);
        }
        else{
            nr_entries = stack_trace_save(entries, MAX_STACK_TRACE, 0 );
        }
        
        u32 stack_hash = jhash(entries, nr_entries * sizeof(unsigned long), 0);

        struct sched_rbentry *new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
        if (!new_entry)
            return;

        struct sched_rbentry *old_entry = rbtree_lookup(nr_entries, entries);
        if (old_entry){
            new_entry->exec_time = old_entry->exec_time + elapsed;    
            rbtree_remove(old_entry);
        }
        new_entry->exec_time = elapsed;
        new_entry->stack_hash = stack_hash;
        memcpy(new_entry->stack_entries, entries, nr_entries * sizeof(unsigned long));
        new_entry->nr_entries = nr_entries;
        
        rbtree_insert(new_entry);
    }
    prev_task = curr;
    prev_timestamp = now;
	return;
}

static int lkp25_p2_proc_show(struct seq_file *m, void *v)
{
	struct rb_node *node;
    int count = 0;
    
    seq_puts(m, "Rank\tJenkins Hash\tTotal CPU Time (ns)\tStack Trace\n");
    spin_lock(&sched_rbtree_lock);
    for (node = rb_last(&sched_rbtree); node && (count < MAX_TOP_TASKS); node = rb_prev(node), count++) {
        struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
        seq_printf(m, "%d\t%u\t%llu\t", count + 1, entry->stack_hash, entry->exec_time);
        for (int i = 0; i < min(entry->nr_entries, MAX_DEPTH); i++)
            seq_printf(m, "%pS ", (void *)entry->stack_entries[i]);
        seq_puts(m, "\n");
    }
    spin_unlock(&sched_rbtree_lock);
    return 0;
}


#endif

#if (P2_PART2 == 1 || P2_PART2 == 2)
static void cleanup_sched_htable(void) {
    struct sched_hentry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(sched_htable, bkt, tmp, entry, hash) {
        hash_del(&entry->hash);
        kfree(entry);
    }

}
#elif (P2_PART2 == 3)
static void cleanup_rbtree(void) {
    struct rb_node *node, *next;
    spin_lock(&sched_rbtree_lock);
    for (node = rb_first(&sched_rbtree); node; node = next) {
        struct sched_rbentry *entry = container_of(node, struct sched_rbentry, node);
        next = rb_next(node);
        rb_erase(node, &sched_rbtree);
        kfree(entry);
    }
    spin_unlock(&sched_rbtree_lock);
}
#endif

static int lkp25_p2_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, lkp25_p2_proc_show, NULL);
}

static const struct proc_ops lkp25_p2_proc_fops = {
	.proc_open = lkp25_p2_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init lkp25_p2_init(void)
{
	int ret;

	printk(KERN_INFO "lkp_p2 Module Loaded");
	/* Create our /proc/perftop file */
	proc_create("perftop", 0, NULL, &lkp25_p2_proc_fops); 


	kp2.post_handler = handler_post2;

	ret = register_kprobe(&kp2);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Planted scheduler kprobe at %p\n", kp2.addr);

	return 0;
}

static void __exit lkp25_p2_exit(void)
{
	/* Remove the /proc/perftop entry */
	unregister_kprobe(&kp2);
	printk(KERN_INFO "Scheduler kprobe at %p unregistered\n", kp2.addr);
	
    #if (P2_PART2 == 1 || P2_PART2 == 2)
    cleanup_sched_htable();
    #elif (P2_PART2 == 3)
    cleanup_rbtree();
    #endif
	remove_proc_entry("perftop", NULL);
	printk(KERN_INFO "lkp_p2 Module Unloaded");
}

module_init(lkp25_p2_init);
module_exit(lkp25_p2_exit);
