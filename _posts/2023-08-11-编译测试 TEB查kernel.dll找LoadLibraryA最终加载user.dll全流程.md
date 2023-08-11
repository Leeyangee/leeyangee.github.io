---
title: 编译测试 Win64线程块查kernel.dll找LoadLibraryA最终加载任意dll全流程
published: true
---
# [](#header-1)0x00、前言  

在编写自己的shellcode时，总会使用windbg调试  
今天写shellcode时正好遇到了一些问题，需要调用user.dll，遂记录一下全过程  

# [](#header-1)0x01、获得kernel.dll地址

众所周知，shellcode想要调用外部dll我们首先需要得到kernel.dll地址，然后根据kernel.dll PE导出表中导出函数名称表的地址遍历查询获得LoadLibraryA地址  
进而继续调用LoadLibraryA('xxx.dll')获得你想要调用的dll地址以调用里面的函数  

如何获得kernel.dll的地址呢？根据windbg调试信息，我们得到了以下可行的构造链:
```
[FS寄存器]                -> TEB地址(线程环境块)
[TEB地址 + 0x30]          -> PEB地址(进程环境块)
[PEB地址 + 0x0c]          -> PEB_LDR_DATA(进程加载的模块信息)
      typedef struct _PEB_LDR_DATA{
        ....
      　LIST_ENTRY InInitializationOrderModuleList;// +0x1c
      } PEB_LDR_DATA,*PPEB_LDR_DATA; // +0x24
[PEB_LDR_DATA地址 + 0x1c] -> IOM地址(模块初始化链表头指针，如上所示)
[IOM地址]                 -> ntdll.dll地址(链表第一个就是ntdll.dll)
[ntdll.dll地址 + 0x08]    -> kernel32.dll地址
```
代码如下：
```
xor edx, edx //清空edx
mov ebx, fs: [edx + 0x30]		
mov ecx, [ebx + 0x0c]			
mov ecx, [ecx + 0x1c]			
mov ecx, [ecx]	
mov ebp, [ecx + 0x08]
```
最后ebp中存放kernel32.dll地址

# [](#header-1)0x02、获得kernel.dll中PE导出表函数名称表内存虚拟地址

获得了kernel32.dll后，需要获得kernel.dll函数名称表内存虚拟地址，以查找函数名称遍历来寻找目标函数地址
```
[kernel.dll地址 + 0x3c]             -> 指向PE头
[kernel.dll地址 + 指向PE头 + 0x78]   -> PE导出表地址
kernel.dll地址 + PE导出表地址        -> PE导出表内存虚拟地址
[PE导出表内存虚拟地址 + 0x20]         -> 函数名称表地址
kernel.dll地址 + 导出函数名称表地址   -> 函数名称表内存虚拟地址
```
代码如下：
```
pushad //保存寄存器环境
mov eax, [ebp + 0x3c]
mov ecx, [ebp + eax + 0x78]
add ecx, ebp
mov ebx, [ecx + 0x20]
add ebx, ebp
```
ecx: kernel.dll函数表内存虚拟地址
ebx: kernel.dll函数名称表内存虚拟地址

# [](#header-1)0x02、循环遍历函数名称表虚拟地址，获得LoadLibraryA地址

获得了函数名称表虚拟地址后，需要获得LoadLibraryA地址，由于懒得写了以下部分采用伪代码 + 汇编来展开
```
for(int32_t i = 0; ; i ++){           // i为当前函数表中第几个函数
      mov esi, [ebx + edi * 4 + i]    // 得到当前函数名地址
      add esi, ebp                    // 得到当前函数名虚拟地址
      //esi: 当前函数名虚拟地址

      for(int32_t j = 0; ; j ++){               // j为当前函数名称中第几个字符
            movsx eax, byte ptr[esi + j]		// 得到当前函数名称 第esi的一个字母
            cmp al, ah				      // 比较到达函数名最后的0没有
            jz compare_hash				// 函数名hash 计算完毕后跳到比较流程
            ror edx, 7				      // 循环右移7位
            add edx, eax				// 累加得到hash
      }
      compare:
      //edx: 当前函数名hash值
      
      mv eax, 0x0c917432      // 0x0c917432是LoadLibraryA的hash值
      cmp edx, eax		// 比较 目标函数名hash 和 当前函数名的hash
      jnz continue;		// 如果 不等于则继续遍历下一个函数

      mov ebx, [ecx + i + 0x24]	// 由函数表虚拟地址 得到 函数序号列表 相对位置
      add ebx, ebp		      // 得到 函数序号列表的 绝对位置
      mov di, [ebx + 2 * edi]		// 得到 当前函数的序号

      mov ebx, [ecx + i + 0x1c]	// 得到 函数地址列表的 相对位置
      add ebx, ebp		      // 得到 函数地址列表的 绝对位置
      add ebp, [ebx + 4 * edi]	// 得到 当前函数的绝对地址

      xchg eax, ebp                 //LoadLibrary函数地址放在eax中
}
```
