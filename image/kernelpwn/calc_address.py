import os

# search -t qword 0x48536677889bfe81
core_ioctl_addr = 0xffffffffc02f115f

core_base       = core_ioctl_addr - 0x15f
core_release    = core_base + 0x0
core_write      = core_base + 0x11
core_read       = core_base + 0x63
core_copy_func  = core_base + 0xf6
core_ioctl      = core_base + 0x15f
init_module     = core_base + 0x1b9
