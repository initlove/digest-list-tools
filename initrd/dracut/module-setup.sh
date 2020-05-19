#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

check() {
    return 255
}

depends() {
    return 0
}

install() {
    if [ ! -e /etc/ima/digest_lists ]; then
        return 0
    fi

    if [ "$(find /etc/ima/digest_lists)" = "/etc/ima/digest_lists" ]; then
        return 0
    fi

    inst_dir /etc/ima/digest_lists
    inst_multiple /etc/ima/digest_lists/*
    inst_binary find
    inst_binary basename
    inst_hook pre-pivot 50 "$moddir/load_digest_lists.sh"
#    inst_binary upload_digest_lists
#    inst_libdir_file "digestlist/libparser-*.so"
#    libc=$(realpath $(ldd /usr/bin/upload_digest_lists | grep libc.so | \
#           awk '{print $3}'))
#    cp -a $libc ${initdir}${libc}
#    libdl=$(realpath $(ldd /usr/bin/upload_digest_lists | grep libdl | \
#            awk '{print $3}'))
#    cp -a $libdl ${initdir}${libdl}
#    ld=$(realpath $(ldd /usr/bin/upload_digest_lists | grep ld-linux | \
#         awk '{print $1}'))
#    cp -a $ld ${initdir}${ld}
#    inst_hook pre-pivot 50 "$moddir/upload_meta_digest_lists.sh"
}
