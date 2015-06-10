obj-m := myfilter.o

all :
		gcc arpcheat.c -lpcap -lpthread -g
	    $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	    $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
		rm a.out
