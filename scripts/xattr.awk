#! /usr/bin/awk -f
{
  if (!length($0)) {
    printf("%.10x%s\0", len, file);
    for (x in xattr) {
      printf("%.8x%s\0", xattr_len[x], x);
      for (i = 0; i < length(xattr[x]) / 2; i++) {
        printf("%c", strtonum("0x"substr(xattr[x], i * 2 + 1, 2)));
      }
    }
    i = 0;
    delete xattr;
    delete xattr_len;
    next;
  };
  if (i == 0) {
    file=$3;
    len=length(file) + 8 + 1;
  }
  if (i > 0) {
    split($0, a, "=");
    xattr[a[1]]=substr(a[2], 3);
    xattr_len[a[1]]=length(a[1]) + 1 + 8 + length(xattr[a[1]]) / 2;
    len+=xattr_len[a[1]];
  };
  i++;
}
