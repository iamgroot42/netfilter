# netfilter


### About
Netfilter-based kernel module that detects the following TCP reconnaissance attacks:
- ACK SCAN (only 'ACK' flag is set, with sequence number = 0)
- FIN SCAN (only 'FIN' flag is set)
- NULL SCAN (no flag is set)
- XMAS SCAN ('FIN', 'PSH' and 'URG' flags are set together)


### Running it
* make clean
* make
* sudo insmod potato.ko
* dmesg | grep iamgroot42
* sudo rmmod potato (to unload module)


### Testing it
* `sudo nmap -sA localhost` to test ACK scan
* `sudo nmap -sF localhost` to test FIN scan
* `sudo nmap -sN localhost` to test NULL scan
* `sudo nmap -sX localhost` to test XMAS scan


### Note
Tested on Ubuntu 16.04; may not work on older versions of Ubuntu/other distributions
