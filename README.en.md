# digest-list-tools

## Description

Integrity Measurement Architecture (IMA) is a software in the Linux kernel for
measuring files accessed with the execve(), mmap() and open() system calls.
Measurements can be reported to a remote verifier or compared to reference
values, for appraisal.

The IMA Digest Lists extension stores in the kernel memory reference values
of OS software, and adds a new entry to the measurement list only if calculated
file digests are not found among those values. This new type of IMA measurement
list which only contains digest lists and unknown files uses a different PCR,
which can be specified in the kernel command line with the option
'ima_digest_list_pcr=#PCR'.

The main purpose of this extension is to overcome one of the main challenges
when OS files are measured: final PCR values when the OS is running cannot be
predicted, as files can be accessed in a different order due to parallel
execution.

With the Digest Lists extension, this problem does not arise as only the
measurement of the preloaded digest lists will be used to update the PCR.
In the good case, the PCR is not further extended if file digests are found in
one of the lists. In the bad case, the PCR is extended with the digest of
unknown files.

The IMA Digest Lists extension can be also used to grant access to files when
appraisal is enabled. There are two possible usages. Access can be granted if
the digest of file content is found in a digest list: this is less secure as
metadata are not taken into account. Access can be granted if the digest of
metadata is found in a digest list; this is more secure as the current value of
extended attributes and inode attributes protected by EVM must match with those
set when the digest list was created (e.g. by the vendor).

More information about the extension can be found at the URL:

https://github.com/euleros/linux/wiki/IMA-Digest-Lists-Extension



## Software Architecture

digest-list-tools provides a set of tools necessary to configure the IMA Digest
Lists extension:

- gen_digest_lists:
  Generates digest lists from different sources, e.g. the RPM database, a RPM
  package or a directory;

- upload_digest_lists:
  Converts digest lists of arbitrary formats to the format supported by the
  kernel; it can also upload converted digest lists to the kernel;

- verify_digest_lists:
  Verifies the integrity of digest lists;

- setup_ima_digest_lists:
  Generates digest lists, and optionally updates the initial ram disk, including
  the digest lists just created;

- setup_ima_digest_list_demo:
  Script with a predefined workflow to create digest lists.

Both upload_digest_lists and gen_digest_lists have a modular design: they can
support additional parsers/generators. Third-party libraries should be placed in
the $libdir/digestlist directory.



### Lifecycle

    gen_digest_lists:
                      +----------------------+
                      | Source (e.g. RPM DB) | (1) provide source
                      +----------------------+
                                 |
                                 |
    +------------+        +-------------+  (3) generate digest list and sign
    | Generator 1|   ...  | Generator N | ---------------------------------|
    +------------+        +-------------+                                  |
    +-----------------------------------+       +-------------+            |
    | Base library (I/O, xattr, crypto) | <---- | Signing Key |            |
    +-----------------------------------+       +-------------+            |
                                           (2) provide signing key         |
                                                             +------+--------------+
                                                             | Sig  |  Digest list |
                                                             |      |    (fmt N)   |
                                                             +------+--------------+
        upload_digest_lists:                                                   |
                             (4) parse digest list (fmt N)                 |
    +----------+             +----------+                                  |
    | Parser 1 |     ...     | Parser N | <--------------------------------|
    +----------+             +----------+
    +-----------------------------------+
    |    Compact list API (generator)   | (5) convert to compact list
    +-----------------------------------+
    +-----------------------------------+             +--------+
    |         Base library (I/O)        | ----------> | Kernel |
    +-----------------------------------+             +--------+
                                          (6) upload compact list



### Digest List Types

Digest list types have been defined to restrict the usage of digest list data
for different purposes.

- COMPACT_KEY:
  This type of digest list contains the public key used to verify the signatures
  of the other digest lists.

- COMPACT_PARSER:
  This type of digest list contains the digests of the parser executable and its
  shared libraries (including the ones that support new digest list formats).
  IMA will not allow user space processes to upload converted digest lists
  unless they have this digest type.

- COMPACT_FILE:
  This type of digest list contains digests of regular files.

- COMPACT_METADATA:
  This type of digest list contains digests of file metadata calculated in the
  same way as for EVM portable signatures.



### Digest List Modifiers

Digest list modifiers are used to provide additional attributes to digest list
types.

- COMPACT_MOD_IMMUTABLE:
  This modifier restricts the usage of the file if appraisal is in enforcing
  mode. Files whose digest has this modifier can be opened only for read.



### Digest List Directory

All digest lists are stored by default in the /etc/ima/digest_lists directory.
The format of the file is as follows:

<#position>-\<digest list type>_list-\<format>-\<filename>

For example, a typical content of the digest list directory is:

```
/etc/ima/digest_lists/0-metadata_list-rpm-libxslt-1.1.29-4.fc27-x86_64
/etc/ima/digest_lists/0-metadata_list-rpm-sqlite-libs-3.20.1-2.fc27-x86_64
/etc/ima/digest_lists/0-metadata_list-rpm-xkeyboard-config-2.22-1.fc27-noarch
```


## Installation
### Use Case - Measurement and Appraisal of Executable Code

This setup procedure can be used to enable appraisal of binaries, shared
libraries and scripts with digest lists.

#### Prerequisite for Measurement

- check the algorithm of digests in the RPM database by executing:
```
  rpm -q systemd --queryformat "%{RPMTAG_FILEDIGESTALGO}\n"
```
  the association between ID and digest algorithms can be retrieved at:
  https://tools.ietf.org/html/rfc4880#section-9.4
- add to the kernel command line:
```
  ima_hash=<hash algo>
```

#### Prerequisite for Appraisal

- generate a signing key and a certificate including the public key;
  certs/signing_key.pem in the kernel source can be used
- convert the certificate to DER format and copy it to /etc/keys:
```
  openssl x509 -in certs/signing_key.pem -out /etc/keys/x509_evm.der \
               -outform der
```
- add an IMA signature to x509_evm.der with the private part of the same key
- remove 'root=<device>' option from the kernel command line and add the
  following line to /etc/dracut.conf:
```
  kernel_cmdline+="root=<device>"
```
- add the following line to /etc/dracut.conf, to include the public key to
  verify the digest lists:
```
  install_items+="/etc/keys/x509_ima.der /etc/keys/x509_evm.der"
```


#### Bootloader Configuration

It is recommended to create the following entries and add the string below to
the kernel comand line:

1) MEASUREMENT
```
   ima_digest_list_pcr=11 ima_policy="tcb|initrd"
```

2) APPRAISAL ENFORCE
```
   ima_digest_list_pcr=11 ima_policy="tcb|initrd|appraise_tcb|appraise_initrd" \
   ima_appraise=digest ima_appraise=enforce-evm
```

#### IMA Policy

The following policy must be written to /etc/ima/ima-policy:

```
measure func=MMAP_CHECK mask=MAY_EXEC
measure func=BPRM_CHECK mask=MAY_EXEC
measure func=MODULE_CHECK
measure func=FIRMWARE_CHECK
measure func=POLICY_CHECK
appraise func=MODULE_CHECK appraise_type=imasig
appraise func=FIRMWARE_CHECK appraise_type=imasig
appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig
appraise func=POLICY_CHECK appraise_type=imasig
appraise func=BPRM_CHECK appraise_type=imasig
appraise func=MMAP_CHECK
```

The imasig requirement cannot be applied to the MMAP_CHECK hook, as some
processes (e.g. firewalld) map as executable files in tmpfs.


#### Setup

In a system with the RPM package manager, digest lists can be generated with the
command:

```
# gen_digest_lists -t metadata -f rpm+db -i l: -o add -p -1 -m immutable \
   -i f:compact -i F:/lib/firmware -i F:/lib/modules -d /etc/ima/digest_lists \
   -i i: -i x: -i e:
```

The command above selects only packaged files with execute bit set and all the
files in the /lib/firmware and /lib/modules directories. It adds both IMA and
EVM digests to the digest lists for all packages in the RPM database.

Without an execution policy hardcoded in the kernel, it is necessary to create a
complete digest list for systemd, as configuration files will be still measured
and appraised until the custom policy is loaded by systemd itself:

```
# gen_digest_lists -t metadata -f rpm+db -i l: -o add -p -1 -m immutable \
   -i f:compact -i F:/lib/firmware -i F:/lib/modules -d /etc/ima/digest_lists \
   -i i: -i x: -i p:systemd
```

With a custom kernel, it is necessary to additionally execute:

```
# gen_digest_lists -t metadata -f compact -i l: -o add -p -1 -m immutable \
   -i I:/lib/modules/`uname -r` -d /etc/ima/digest_lists -i i: -i x:
```

Other files not known by the package manager can be also added to a digest list:
```
# gen_digest_lists -t metadata -f unknown -i l: -o add -p -1 -m immutable \
   -i D:/etc/ima/digest_lists -i I:<desired directory> -d /etc/ima/digest_lists \
   -i i: -i x: -i e:
```

After digest lists are created, they must be signed with evmctl:

```
# evmctl sign -o -a sha256 --imahash --key <private key> -r \
   /etc/ima/digest_lists
```

Regenerate the initial ram disk and include the custom IMA policy:

```
# dracut -f -exattr -I /etc/ima/ima-policy
```

In order to execute the command above, that includes extended attributes in the
initial ram disk, it is necessary to apply the patches available at:

https://github.com/euleros/cpio/tree/xattr-v1  
https://github.com/euleros/dracut/tree/digest-lists


Digest lists will be automatically included in the initial ram disk by the new
dracut module 'digestlist', part of this software. Its configuration file is in
/etc/dracut.conf.d.


#### Boot Process

Digest lists are loaded as early as possible during the boot process, so that
digests can be found before file are accessed. The kernel reads and parses the
digest lists in the /etc/ima/digest_lists directory.


#### Software Update

If new RPMs are installed on the system, new digest lists must be created with
the same commands introduced above. The new digest lists are not automatically
loaded at boot until the initial ram disk is regenerated. A systemd service will
be developed to load new digest lists without regenerating the initial ram disk.



### Use Case - Immutable and Mutable Files (with HMAC Key)

The steps described below represent only a configuration example. The list of
files that should be included in the digest lists and the type (immutable or
mutable) depend on user requirements. The setup process is organized in two
different steps. First, the system is booted in rescue mode so that digest of
mutable files can be reliably calculated (there is no process accessing them).

During the first step, the administrator launches the
setup_ima_digest_lists_demo script to create digest lists for the system.
It might be done by the software vendor if the content of all files that will
be measured/appraised is known in advance. Otherwise, the administrator becomes
responsible for the initial values of the files that will be accessed by the
system, by signing the digest lists. At this stage, the HMAC key is not yet
available. It will be created and sealed once the digest lists are generated.

For the second step, the administrator runs the system in the final
configuration, so that the HMAC key can be unsealed, but still selects the
rescue mode. During this step, the administrator launches again the
setup_ima_digest_lists_demo script to add a HMAC to every file verified with
the digest lists.

#### Prerequisite for measurement:

- add 'iversion' mount option in /etc/fstab (if the filesystem supports it)
- check the algorithm of digests in the RPM database by executing:
```
  rpm -q systemd --queryformat "%{RPMTAG_FILEDIGESTALGO}\n"
```
  the association between ID and digest algorithms can be retrieved at:
  https://tools.ietf.org/html/rfc4880#section-9.4
- add to the kernel command line:
```
  ima_hash=<hash algo>
```

#### Prerequisite for appraisal:

- generate a signing key and a certificate including the public key;
  certs/signing_key.pem in the kernel source can be used
- convert the certificate to DER format and copy it to /etc/keys:
```
  openssl x509 -in certs/signing_key.pem -out /etc/keys/x509_ima.der \
               -outform der
```
- generate EVM keys; follow instructions at
  https://sourceforge.net/p/linux-ima/wiki/Home/, section 'Creating trusted and
  EVM encrypted keys'
- remove 'root=<device>' option from the kernel command line and add the
  following line to /etc/dracut.conf:
```
  kernel_cmdline+="root=<device>"
```
- copy the following dracut modules from the GIT repository at
  https://github.com/dracutdevs/dracut to /usr/lib/dracut/modules.d:
```
  96securityfs 97masterkey 98integrity
```
- include dracut modules in the ram disk by adding to /etc/dracut.conf:
```
  add_dracutmodules+=" securityfs masterkey integrity"
```
- add the following lines to /etc/dracut.conf, to include the public key to
  verify the digest lists, and the EVM keys:
```
  install_items+="/etc/keys/x509_ima.der"
  install_items+="/etc/keys/kmk-trusted.blob /etc/keys/evm-trusted.blob"
```
  (in the last line, replace kmk-trusted with kmk-user if a user key was used as
  masterkey)
- add the following line to /etc/dracut.conf, to include SELinux labels in the
  initial ram disk:
```
  install_items+="/etc/selinux/targeted/contexts/files/file_contexts"
  install_items+=/etc/selinux/targeted/contexts/files/file_contexts.subs_dist"
```


#### Bootloader Configuration

It is recommended to create the following entries and add the string below
to the kernel comand line:

1) SETUP
```
   systemd.unit=setup-ima-digest-lists.service
```

2) MEASUREMENT
```
   ima_digest_list_pcr=11 ima_policy="tcb|initrd"
```

3) APPRAISAL ENFORCE SETUP
```
   ima_digest_list_pcr=11 ima_policy="tcb|initrd|appraise_tcb|appraise_initrd| \
   appraise_tmpfs" ima_appraise=digest ima_appraise=enforce-evm evm=random
   systemd.unit=setup-ima-digest-lists.service
```

4) APPRAISAL ENFORCE
```
   ima_digest_list_pcr=11 ima_policy="tcb|initrd|appraise_tcb|appraise_initrd| \
   appraise_tmpfs" ima_appraise=digest ima_appraise=enforce-evm evm=random
```

5) APPRAISAL PERMISSIVE
```
   ima_digest_list_pcr=11 ima_policy="tcb|initrd|appraise_tcb|appraise_initrd| \
   appraise_tmpfs" ima_appraise=digest ima_appraise=log-evm evm=random
```


#### Setup - First Phase

##### With RPM Package Manager

digest-list-tools includes a script called setup_ima_digest_lists_demo to
simplify the creation of digest lists. It will create the following digest
lists:

- digest lists from package manager
- digest list of unknown files in the initial ram disk (some are generated by
  dracut)
- digest list of IMA policy
- digest list of unknown files in the root filesystem so that appraisal can be
  enabled (important: digest of metadata will be created from the current value
  of extended attributes; they must be checked by the administrator before the
  digest list is generated and signed)

1) Execute:

```
# setup_ima_digest_lists_demo initial [signing key] [X.509 certificate]
```

The procedure is interactive and the script asks the user to confirm/edit the
list of files whose digest will be included in the digest list.

2) Reboot

Reboot the system to load the new digest lists during the boot process.


##### Without RPM Package Manager

An alternative way to create a digest list is to directly take file digests from
the filesystem without using the package manager. To do that, it is sufficient
to edit setup_ima_digest_lists_demo and to comment the line that begins with
'setup_ima_digest_lists distro'.


#### Setup - Second Phase

After the first phase of the setup, /etc/ima/digest_lists contains all the
digest lists necessary to boot the system with appraisal enabled and enforced.
The remaining step is to add a HMAC to every file added to the digest lists.

1) Execute:

```
# setup_ima_digest_lists_demo final
```

### Software Update

#### Generation

Digest lists can be generated with the gen_digest_lists tool. A description of
this command can be obtained by executing the command:

```
$ man gen_digest_lists
```

#### Upload

After digest lists have been generated, they can be uploaded by executing the
command:

```
# upload_digest_lists
```

### Integrity Verification

The measurement list, after loading the digest lists, will look like:

```
11 <digest> ima-ng <digest> boot_aggregate
11 <digest> ima-ng <digest> /etc/keys/x509_ima.der
11 <digest> ima-ng <digest> [...]/0-parser_list-compact-upload_digest_lists
11 <digest> ima-ng <digest> [...]/0-key_list-signing_key.der
11 <digest> ima-ng <digest> [...]/1-parser_list-compact-libparser-ima.so
11 <digest> ima-ng <digest> [...]/2-parser_list-compact-libparser-rpm.so
11 <digest> ima-ng <digest> [...]/0-file_list-rpm-libxslt-1.1.29-4.fc27-x86_64
...
<measurement entries for modified mutable files>
```

An attestation server can use the verify_digest_lists tool to verify the
integrity of digest lists. For example, it can execute:

```
$ verify_digest_lists
```


## Author
Written by Roberto Sassu, <roberto.sassu at huawei.com>.



## Copying
Copyright (C) 2018-2020 Huawei Technologies Duesseldorf GmbH. Free use of this
software is granted under the terms of the GNU Public License 2.0 (GPLv2).
