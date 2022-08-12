# hidefile-kernel-module

A simple kernel module who hides a file by hooking the getdents64 syscall.

## Usage

First go to idanm.c and find the FILE_TO_HIDE macro, then replace it with the path to the file you want to hide.

Now you will have to compile the module, by using the following command:

```bash
make
```

Then you will have to load the module, use the following command:

```bash
sudo insmod hidefile.ko
```

## Reverting

To unload the module, use the following command:

```bash
sudo rmmod hidefile
```

To delete the out data, use the following command:

```bash
make clean
```
