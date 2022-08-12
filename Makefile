# CONFIG_MODULE_SIG=n

obj-m += idanm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	insmod idanm.ko && echo 'ls:' && ls && rmmod idanm
