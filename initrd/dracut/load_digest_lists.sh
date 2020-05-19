#! /bin/bash

if [ ! -f /sys/kernel/security/ima/digest_list_data ]; then
	exit 0
fi

for f in $(find $NEWROOT/etc/ima/digest_lists -type f); do
	if [ ! -f /etc/ima/digest_lists/$(basename $f) ]; then
		echo $f > /sys/kernel/security/ima/digest_list_data
	fi
done
