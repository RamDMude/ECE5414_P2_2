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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ram Mude");
MODULE_DESCRIPTION("LKP25 P2");

/* HASH TABLE BEGIN */

/*
 * Let's make a hash table with 2^10 = 1024 bins
 */
#define MY_HASH_TABLE_BINS 10
#define MAX_STACK_TRACE 16
static DEFINE_HASHTABLE(sched_htable, MY_HASH_TABLE_BINS);

/* Hashtable entry struct */
struct sched_hentry {
    unsigned long stack_entries[MAX_STACK_TRACE];
    unsigned int nr_entries;
    int count;
    struct hlist_node hash;
};
/* HASH TABLE END */

// static char symbol[KSYM_NAME_LEN] = "lkp25_p2_proc_open";
// module_param_string(symbol, symbol, KSYM_NAME_LEN, 0644);

// static struct kprobe kp = {
// 	.symbol_name	= symbol,
// };

static char symbol2[KSYM_NAME_LEN] = "pick_next_task_fair";
module_param_string(symbol2, symbol2, KSYM_NAME_LEN, 0644);

static struct kprobe kp2 = {
	.symbol_name	= symbol2,
};

// int cat_counter = 0;

// /* kprobe post_handler: called after the probed instruction is executed */
// static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
// {
// 	cat_counter++;
// }


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

static void cleanup_sched_htable(void) {
    struct sched_hentry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(sched_htable, bkt, tmp, entry, hash) {
        hash_del(&entry->hash);
        kfree(entry);
    }

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

static int lkp25_p2_proc_open(struct inode *inode, struct file *file)
{
	// printk(KERN_INFO "Perftop Opened");
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

	// kp.post_handler = handler_post;

	// ret = register_kprobe(&kp);
	// if (ret < 0) {
	// 	pr_err("register_kprobe failed, returned %d\n", ret);
	// 	return ret;
	// }
	// printk(KERN_INFO "Planted cat kprobe at %p\n", kp.addr);


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
	// unregister_kprobe(&kp);
	// printk(KERN_INFO "Cat kprobe at %p unregistered\n", kp.addr);
	unregister_kprobe(&kp2);
	printk(KERN_INFO "Scheduler kprobe at %p unregistered\n", kp2.addr);
	cleanup_sched_htable();
	remove_proc_entry("perftop", NULL);
	printk(KERN_INFO "lkp_p2 Module Unloaded");
}

module_init(lkp25_p2_init);
module_exit(lkp25_p2_exit);
