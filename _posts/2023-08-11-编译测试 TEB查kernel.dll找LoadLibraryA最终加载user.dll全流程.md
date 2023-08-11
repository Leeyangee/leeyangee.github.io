---
title: 编译测试 线程块查kernel.dll找LoadLibraryA最终加载user.dll全流程
published: true
---
# [](#header-1)0x00、前言  

在编写自己的shellcode时，总会使用windbg调试  
今天写shellcode时正好遇到了一些问题，需要调用user.dll，遂记录一下全过程  

# [](#header-1)0x00、开始  

众所周知，shellcode想要调用外部dll我们首先需要得到kernel.dll地址，然后根据kernel.dll PE导出表中导出函数名称表的地址获得LoadLibraryA地址  
继而调用LoadLibraryA('xxx.dll')获得你想要调用的dll地址以调用里面的函数  

如何获得kernel.dll的地址呢？根据windbg调试信息，我们得到了以下可行的构造链:
```
[FS寄存器]                -> TEB地址(线程环境块)
[TEB地址 + 0x30]          -> PEB地址(进程环境块)
[PEB地址 + 0x0c]          -> PEB_LDR_DATA(进程加载的模块信息)
      typedef struct _PEB_LDR_DATA{
        ....
      　LIST_ENTRY InInitializationOrderModuleList;// +0x1c
      } PEB_LDR_DATA,*PPEB_LDR_DATA; // +0x24
[PEB_LDR_DATA地址 + 0x1c] -> IOM地址(模块初始化链表头指针)
[IOM地址]                 -> ntdll.dll地址(链表第一个就是ntdll.dll)
[ntdll.dll地址 + 0x08]    -> kernel32.dll地址
```
代码如下：
```
mov ebx, fs: [edx + 0x30]		
mov ecx, [ebx + 0x0c]			
mov ecx, [ecx + 0x1c]			
mov ecx, [ecx]	
mov ebp, [ecx + 0x08]
```
最后ebp内即kernel32.dll地址

