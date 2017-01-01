#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

MODULE_AUTHOR("test");
MODULE_LICENSE("GPL");

static int nbr	= 10;
module_param(nbr, int , S_IRUGO);

static int __init test_init(void)
{
	int i;
	
	for(i=0; i<nbr; i++)
	{
		printk(KERN_ALERT "hello, test:%d\n", i);
	}

	return 0;
}

static void __exit test_exit(void)
{
	printk(KERN_ALERT "test module has been unloaded.\n");
}

module_init(test_init);
module_exit(test_exit);
