---
title: 浅谈ShellCode Windows查kernel.dll找LoadLibraryA最终加载任意dll全流程
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
xor edx, edx 				//清空edx
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
pushad 					//保存寄存器环境
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
            movsx eax, byte ptr[esi + j]	// 得到当前函数名称 第esi的一个字母
            cmp al, ah				// 比较到达函数名最后的0没有
            jz compare_hash			// 函数名hash 计算完毕后跳到比较流程
            ror edx, 7				// 循环右移7位
            add edx, eax			// 累加得到hash
      }
      compare:
      //edx: 当前函数名hash值
      
      mv eax, 0x0c917432      	// 0x0c917432是LoadLibraryA的hash值
      cmp edx, eax		// 比较 目标函数名hash 和 当前函数名的hash
      jnz continue;		// 如果 不等于则继续遍历下一个函数

      mov ebx, [ecx + i + 0x24]		// 由函数表虚拟地址 得到 函数序号列表 相对位置
      add ebx, ebp		      	// 得到 函数序号列表的 绝对位置
      mov di, [ebx + 2 * edi]		// 得到 当前函数的序号

      mov ebx, [ecx + i + 0x1c]		// 得到 函数地址列表的 相对位置
      add ebx, ebp		      	// 得到 函数地址列表的 绝对位置
      add ebp, [ebx + 4 * edi]		// 得到 当前函数的绝对地址

      xchg eax, ebp                 	//LoadLibrary函数地址放在eax中
}

pop edi				// pushad中最后一个压入的是edi 正好是开始预留 用于存放的三个函数地址 的栈空间
push 0x00003233                 
push 0x72657375                 
push esp                        // "user32"
stosd				// 把找到函数地址出入 edi对应的栈空间
push edi    			// 继续压栈 平衡栈
popad				// 还原环境

```
现在基本上就结束了，只需要call[edi - 0x8]即可
```
call[edi - 0x8]
```
调用结束后eax中存放user32.dll地址

# [](#header-1)0x03、调用user.dll MessageBox全流程

调用user.dll MessageBox全流程代码，以下使用内联汇编程序演示: 
```
#pragma comment(linker,"/SECTION:.data,RWE")
#include <iostream>
#include <windows.h>

void main() {
	__asm {
		nop
		nop	// 内存中占位方便观察
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		CLD                             // 清空标志位DF
		push 0x1e380a6a		        // 压入 MessageBoxA 字符串的hash
		push 0x4fd18963	    	        // 压入 ExitProcess 字符串的hash
		push 0x0c917432 		// 压入 LoadLibraryA 字符串的hash
		mov esi, esp	       	  	// 指向栈中存放LoadLibraryA的 hash 地址
		lea edi, [esi - 0xc]	        // 用于存放后边找到的 三个函数地址

		// 开辟0x400大小的栈空间
		xor ebx, ebx
		mov bh, 0x04
		sub esp, ebx

		// 将user32.dll入栈
		mov bx, 0x3233
		push ebx                        // 压入字符'32'
		push 0x72657375                 // 压入字符 'user'
		push esp
		xor edx, edx

		// 查找 kernel32.dll 的基地址
		mov ebx, fs: [edx + 0x30]		// FS得到当前线程环境块TEB TEB+0x30 是进程环境块 PEB
		mov ecx, [ebx + 0x0c]			// PEB+0x0c 是PEB_LDR_DATA结构体指针 存放这已经被进程加载的动态链接库的信息
		mov ecx, [ecx + 0x1c]			// PEB_LDR_DATA+0x1c 指向模块初始化链表的头指针 InInitalizationOrderModuleList
		mov ecx, [ecx]				// 进入链表第一个就是ntdll.dll
		mov ebp, [ecx + 0x08]			// ebp: kernel32.dll基地址

		// 与 hash 的查找相关
		find_lib_funcs :
		      	lodsd				// [esi]4字节传到eax中
		      	cmp eax, 0x1e380a6a 		// 0x1e380a6a: MessageBoxA的hash值
		      	jne find_funcs                  // 如果不相等则继续查找
		      	xchg eax, ebp			// 记录当前hash值
      			call[edi - 0x8]
      			xchg eax, ebp			// 还原当前hash值 并且把exa基地址更新为 user32.dll的基地址

		// 在PE文件中查找相应的API函数
		find_funcs :
		      	pushad					// 保存寄存器环境
			mov eax, [ebp + 0x3c]			// PE头
			mov ecx, [ebp + eax + 0x78]		// 得到导出表的指针
			add ecx, ebp				// 得到导出函数表内存虚拟地址(VA)
			mov ebx, [ecx + 0x20]			// 得到导出函数名称表(RVA)
			add ebx, ebp				// 得到导出函数名称表内存虚拟地址(VA)
			xor edi, edi				// 清空计数器

		// 循环读取函数名称表
            	next_func_loop :
                  	inc edi					// 函数计数器+1
                  	mov esi, [ebx + edi * 4]		// 得到 当前函数名的地址(RVA)
                  	add esi, ebp				// 得到 当前函数名的内存虚拟地址(VA)
                  	cdq;

		// 计算hash值
	      	hash_loop:					      
		      	movsx eax, byte ptr[esi]		// 得到当前函数名称 第esi的一个字母
			cmp al, ah				// 比较到达函数名最后的0没有
			jz compare_hash				// 函数名hash 计算完毕后跳到 下一个流程
			ror edx, 7				// 循环右移7位
			add edx, eax				// 累加得到hash
			inc esi					// 计数+1 得到函数名的下一个字母
			jmp hash_loop				  

			// hash值的比较
            	compare_hash :
		      	cmp edx, [esp + 0x1c]			// 比较 目标函数名hash 和 当前函数名的hash
			jnz next_func_loop			// 如果 不等于 继续下一个函数名
			mov ebx, [ecx + 0x24]			// 得到 函数序号列表的 相对位置
			add ebx, ebp				// 得到 函数序号列表的 绝对位置
			mov di, [ebx + 2 * edi]			// 得到 当前函数的序号
			mov ebx, [ecx + 0x1c]			// 得到 函数地址列表的 相对位置
			add ebx, ebp				// 得到 函数地址列表的 绝对位置
			add ebp, [ebx + 4 * edi]		// 得到 当前函数的绝对地址 
								// 循环依次得到kernel32.dll中的 LoadLibraryA  ExitProcess
								// 和user32.dll中的 MessageBoxA

			xchg eax, ebp				// 把函数地址放入eax中
			pop edi					// pushad中最后一个压入的是edi 正好是开始预留 用于存放的三个函数地址 的栈空间
			stosd					// 把找到函数地址出入 edi对应的栈空间
			push edi				// 平衡栈
			popad					// 还原环境
			cmp eax, 0x1e380a6a			    
			jne find_lib_funcs

		// 下方的代码，就是弹窗
            	func_call :
		      	xor ebx, ebx		// 将 ebx 清0
			push ebx
			push 0x20202067
			push 0x75625f61
			push 0x7965656c
			mov eax, esp		// "leeya_bug"
			push ebx
			push 0x2020206b		
			push 0x6f207473
			push 0x65742067
			push 0x75625f61	
			push 0x7965656c 
			mov ecx, esp		// "leeya_bug test ok"

			push ebx		// messageBox 第四个参数
			push eax		// messageBox 第三个参数
			push ecx		// messageBox 第二个参数
			push ebx		// messageBox 第一个参数

			call[edi - 0x04]	// 调用	MessageBoxA
			push ebx
			call[edi - 0x08]	// 调用 ExitProcess
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
			nop
	}
}
```
