##########################################################################
# File Name: chmod.sh
# Author: amoscykl
# mail: amoscykl980629@163.com
# Created Time: Wed 22 Jan 2020 12:22:20 AM PST
#########################################################################
#!/bin/zsh
PATH=/home/edison/bin:/home/edison/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/work/tools/gcc-3.4.5-glibc-2.3.6/bin
export PATH

chmod +x $1
if [ -n "$2" ]
	then	chmod +x $2
fi

checksec $1

touch a.py
echo "from pwn import *" > a.py
if [ ! -n "$2" ]
	then echo "from LibcSearcher import *" >> a.py
fi
echo "context.log_level = 'debug'" >> a.py
echo "" >> a.py
echo "#r = remote('', )" >> a.py
echo "r = process('./$1')" >> a.py
echo "elf = ELF('./$1')" >> a.py
if [ -n "$2" ]
then	echo "libc = ELF('./$2')" >> a.py
fi
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "" >> a.py
echo "r.interactive()" >> a.py
