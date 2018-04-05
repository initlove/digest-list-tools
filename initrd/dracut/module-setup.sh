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
    mkdir -m 0755 -p ${initdir}/etc/ima
    cp /usr/bin/upload_digest_lists ${initdir}/usr/bin/upload_digest_lists
    cp -a /etc/ima/digest_lists ${initdir}/etc/ima
}
