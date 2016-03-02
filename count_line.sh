#!/usr/bin/env bash
tot=0
for files in $(find . -iname "*.h" -or -iname "*.c")
do 
	file=$(wc -l $files|cut -d' ' -f1)
	echo -e $files":\t"$file
	tot=$[$tot+$file]
done
echo -e "\n\nTotal: "$tot
