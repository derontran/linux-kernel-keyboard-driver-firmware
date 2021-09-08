### Warning: Don't run this program on your machine but your choice of linux VM 

### How to run
1. use "make build" to compile the module 
2. then "sudo insmod interrupt.ko" to load it into kernel
3. then "make clean" to cleanup 
4. finally "sudo rmmod clock.ko" to remove it from your kernel 