#ifndef __IDANM_DRIVER_H__
#define __IDANM_DRIVER_H__

#include <linux/fs.h>
#include <linux/cdev.h>

#define HIDEFILE_MAJOR 42
/* only one device */
#define MAX_HIDEFILE_MINOR 1

enum hidefile_operation
{
    HIDEFILE_OP_ADD,
    HIDEFILE_OP_REMOVE
};

struct hidefile_device_data
{
    struct cdev cdev;
};

/* Function prototypes */
int init_driver(void);
void cleanup_driver(void);

#endif /* __IDANM_DRIVER_H__ */