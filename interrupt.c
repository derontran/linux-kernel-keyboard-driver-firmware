#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/module.h> /* Specifically, a module */
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>  /* For spin lock*/
#include <linux/workqueue.h>
#include <linux/interrupt.h> /* We want an interrupt */
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/keyboard.h>
#include <linux/kd.h>
// #include <linux/kdb.h>
#include <linux/ctype.h>
#include <linux/io.h>
#include <linux/string.h>

#define MY_WORK_QUEUE_NAME "WQsched.c"
#define MAX_BUFFER 16
static DEFINE_SPINLOCK(lock_buffer);
static struct proc_dir_entry *ent;
static char buffer[MAX_BUFFER];
static int in=0; 
static int out=0;
static struct workqueue_struct *my_workqueue;

/* KEY MAP */ 
/*______________________________________________________________________________*/

u_short plain_map[NR_KEYS] = {
	0xf200,	0xf01b,	0xf031,	0xf032,	0xf033,	0xf034,	0xf035,	0xf036,
	0xf037,	0xf038,	0xf039,	0xf030,	0xf02d,	0xf03d,	0xf07f,	0xf009,
	0xfb71,	0xfb77,	0xfb65,	0xfb72,	0xfb74,	0xfb79,	0xfb75,	0xfb69,
	0xfb6f,	0xfb70,	0xf05b,	0xf05d,	0xf201,	0xf702,	0xfb61,	0xfb73,
	0xfb64,	0xfb66,	0xfb67,	0xfb68,	0xfb6a,	0xfb6b,	0xfb6c,	0xf03b,
	0xf027,	0xf060,	0xf700,	0xf05c,	0xfb7a,	0xfb78,	0xfb63,	0xfb76,
	0xfb62,	0xfb6e,	0xfb6d,	0xf02c,	0xf02e,	0xf02f,	0xf700,	0xf30c,
	0xf703,	0xf020,	0xf207,	0xf100,	0xf101,	0xf102,	0xf103,	0xf104,
	0xf105,	0xf106,	0xf107,	0xf108,	0xf109,	0xf208,	0xf209,	0xf307,
	0xf308,	0xf309,	0xf30b,	0xf304,	0xf305,	0xf306,	0xf30a,	0xf301,
	0xf302,	0xf303,	0xf300,	0xf310,	0xf206,	0xf200,	0xf03c,	0xf10a,
	0xf10b,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
	0xf30e,	0xf702,	0xf30d,	0xf01c,	0xf701,	0xf205,	0xf114,	0xf603,
	0xf118,	0xf601,	0xf602,	0xf117,	0xf600,	0xf119,	0xf115,	0xf116,
	0xf11a,	0xf10c,	0xf10d,	0xf11b,	0xf11c,	0xf110,	0xf311,	0xf11d,
	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
};
u_short shift_map[NR_KEYS] = {
	0xf200,	0xf01b,	0xf021,	0xf040,	0xf023,	0xf024,	0xf025,	0xf05e,
	0xf026,	0xf02a,	0xf028,	0xf029,	0xf05f,	0xf02b,	0xf07f,	0xf009,
	0xfb51,	0xfb57,	0xfb45,	0xfb52,	0xfb54,	0xfb59,	0xfb55,	0xfb49,
	0xfb4f,	0xfb50,	0xf07b,	0xf07d,	0xf201,	0xf702,	0xfb41,	0xfb53,
	0xfb44,	0xfb46,	0xfb47,	0xfb48,	0xfb4a,	0xfb4b,	0xfb4c,	0xf03a,
	0xf022,	0xf07e,	0xf700,	0xf07c,	0xfb5a,	0xfb58,	0xfb43,	0xfb56,
	0xfb42,	0xfb4e,	0xfb4d,	0xf03c,	0xf03e,	0xf03f,	0xf700,	0xf30c,
	0xf703,	0xf020,	0xf207,	0xf10a,	0xf10b,	0xf10c,	0xf10d,	0xf10e,
	0xf10f,	0xf110,	0xf111,	0xf112,	0xf113,	0xf213,	0xf203,	0xf307,
	0xf308,	0xf309,	0xf30b,	0xf304,	0xf305,	0xf306,	0xf30a,	0xf301,
	0xf302,	0xf303,	0xf300,	0xf310,	0xf206,	0xf200,	0xf03e,	0xf10a,
	0xf10b,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
	0xf30e,	0xf702,	0xf30d,	0xf200,	0xf701,	0xf205,	0xf114,	0xf603,
	0xf20b,	0xf601,	0xf602,	0xf117,	0xf600,	0xf20a,	0xf115,	0xf116,
	0xf11a,	0xf10c,	0xf10d,	0xf11b,	0xf11c,	0xf110,	0xf311,	0xf11d,
	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,	0xf200,
};

/* Kdb Keyboard */
/*______________________________________________________________________________*/

/* Keyboard Controller Registers on normal PCs. */

#define KBD_STATUS_REG		0x64	/* Status register (R) */
#define KBD_DATA_REG		0x60	/* Keyboard data register (R/W) */

/* Status Register Bits */

#define KBD_STAT_OBF 		0x01	/* Keyboard output buffer full */
#define KBD_STAT_MOUSE_OBF	0x20	/* Mouse output buffer full */

static int kbd_last_ret;

/*
 * Check if the keyboard controller has a keypress for us.
 * Some parts (Enter Release, LED change) are still blocking polled here,
 * but hopefully they are all short.
 */
int kdb_get_kbd_char(unsigned char scancode, unsigned char scanstatus)
{
	
	static int shift_lock;	/* CAPS LOCK state (0-off, 1-on) */
	static int shift_key;	/* Shift next keypress */
	static int ctrl_key;
	u_short keychar;

	/*
	 * Ignore release, trigger on make
	 * (except for shift keys, where we want to
	 *  keep the shift state so long as the key is
	 *  held down).
	 */

	if (((scancode&0x7f) == 0x2a) || ((scancode&0x7f) == 0x36)) {
		/*
		 * Next key may use shift table
		 */
		if ((scancode & 0x80) == 0)
			shift_key = 1;
		else
			shift_key = 0;
		return -1;
	}

	if ((scancode&0x7f) == 0x1d) {
		/*
		 * Left ctrl key
		 */
		if ((scancode & 0x80) == 0)
			ctrl_key = 1;
		else
			ctrl_key = 0;
		return -1;
	}

	if ((scancode & 0x80) != 0) {
		if (scancode == 0x9c)
			kbd_last_ret = 0;
		return -1;
	}

	scancode &= 0x7f;

	/*
	 * Translate scancode
	 */

	if (scancode == 0x3a) {
		/*
		 * Toggle caps lock
		 */
        shift_lock ^= 1;

#ifdef	KDB_BLINK_LED
		kdb_toggleled(0x4);
#endif
		return -1;
	}

	if (scancode == 0xe0)
		return -1;

	/*
	 * For Japanese 86/106 keyboards
	 * 	See comment in drivers/char/pc_keyb.c.
	 * 	- Masahiro Adegawa
	 */
	if (scancode == 0x73)
		scancode = 0x59;
	else if (scancode == 0x7d)
		scancode = 0x7c;

	if (!shift_lock && !shift_key && !ctrl_key) {
		keychar = plain_map[scancode];
	} else if (shift_key) {
		keychar = shift_map[scancode];
	} else 
		return -1;
	keychar &= 0x0fff;
	if (keychar == '\t')
		keychar = ' ';
	switch (KTYP(keychar)) {
	case KT_LETTER:
	case KT_LATIN:
		if (isprint(keychar))
			break;		/* printable characters */
		/* fall through */
	
	default:
		return -1;	/* ignore unprintables */
	}

	

	return keychar & 0xff;
}


/* Interrupt Service */
/*______________________________________________________________________________*/


static void write_buffer(char value)
{
    if((in - out)==(MAX_BUFFER-1) || (out-in)==1);  // full, drop
    else
    {   
        buffer[in]=value;
        in = (in+1) % MAX_BUFFER;

    }
    
}

struct ourdata
{
		struct work_struct task;
		unsigned char scancode;
		unsigned char status;

};

/* 
 * This will get called by the kernel as soon as it's safe
 * to do everything normally allowed by kernel modules.
 */
static void got_char(struct work_struct * work)
{
    // get our data 
	char keychar;
    struct ourdata *data = container_of(work,struct ourdata ,task); // ourdaa.data or data ?
    printk(KERN_INFO "Scan Code %s.\n",(data->scancode & 0x80 ? "Release" : "Pressed"));
    keychar= kdb_get_kbd_char(data->scancode, data->status);
    if(keychar!=-1)
	{
		printk(KERN_INFO "receive key: %c", keychar);
    	spin_lock(&lock_buffer);
 		write_buffer(keychar);
    	spin_unlock(&lock_buffer);
	}

    kfree(data);
}


/* 
 * This function services keyboard interrupts. It reads the relevant
 * information from the keyboard and then puts the non time critical
 * part into the work queue. This will be run when the kernel considers it safe.
 */
static irqreturn_t irq_handler(int irq, void *dev_id)
{
    /* 
	 * This variables are static because they need to be
	 * accessible (through pointers) to the bottom half routine.
	 */
	struct ourdata * data;
    
	data = (struct ourdata *)kmalloc(sizeof(struct ourdata), GFP_ATOMIC);

	/* 
	* Read keyboard status
	*/
	data->status = inb(0x64);
	data->scancode = inb(0x60);

	INIT_WORK(&(data->task), got_char);
      
   
    schedule_work(&data->task);

    return IRQ_HANDLED;
}


static ssize_t key_read(struct file *file,
                        char __user *ubuf, size_t count,
                        loff_t *ppos)
{
    int ret=0;
	char localbuff[16] ="";

	if ((*ppos) > 0)  // first time read ?
		ret = 0;
	else // go ahead and read all in once time only
	{
		printk(KERN_INFO "read....\n");
		*ppos = ret+100;  // just random set a non-zero 
		
		/* lock for read */
		spin_lock(&lock_buffer);
		if(in!=out)
		{
			if(in>out)
			{
				strncat(localbuff,buffer+out,in-out);
			}
			else if(in<out)
			{
				strncat(localbuff,buffer+out,16-out);
				strncat(localbuff,buffer,in);
			}
			out=in;
			
		}
		spin_unlock(&lock_buffer);
		
		ret = strlen(localbuff);
		if(ret>0)
		{
			printk(KERN_INFO "buffer : %s",localbuff);
			copy_to_user(ubuf,localbuff, strlen(localbuff));		
		}
    
    }
    
    return ret;
}
static struct file_operations myops = {
    .owner = THIS_MODULE,
    .read = key_read,
};

static int simple_init(void)
{
    printk(KERN_INFO "hello...\n");

    ent = proc_create("keybuff", 0660, NULL, &myops);
    my_workqueue = create_workqueue(MY_WORK_QUEUE_NAME);

    return request_irq(1,           /* The number of the keyboard IRQ on PCs */
                    (irq_handler_t) irq_handler, /* our handler */
                    IRQF_SHARED, "test_keyboard_irq_handler",
                    (void *)(irq_handler));
  
    return 0;
}
static void simple_cleanup(void)
{
    free_irq(1, irq_handler);
    proc_remove(ent);
    printk(KERN_INFO "bye....\n");
}


module_init(simple_init);
module_exit(simple_cleanup);

MODULE_LICENSE("GPL");