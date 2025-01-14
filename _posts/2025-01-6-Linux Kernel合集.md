---
title: Linux Kernel 驱动提权合集 - 未更完
published: true
---

在 Linux 操作系统中 CPU 的特权级别分为四个等级：  
Ring 0、Ring 1、Ring 2、Ring 3

Ring 0 只给 OS 使用，Ring 3 运行在这个操作系统上的全部程序都可以使用  
Ring 0 可以调用系统所有资源，包括外层 Ring

提权漏洞则是由外层 Ring 通过某些特殊手段到 Ring 0 的一个过程

# [](#header-3)Kernel 详解

### [](#header-3)系统态是什么？系统态和提权有什么关系？

系统态，也称为内核态（Kernel Mode），是操作系统中的一种执行模式

在系统态下，程序运行在操作系统的核心（内核）中，拥有对硬件资源的完全访问权限 (即 Ring 0 权限)  
与此相对的是用户态（User Mode），用户态是普通应用程序运行的模式，受限于操作系统的权限和安全性，无法直接访问硬件资源或执行内核操作

### [](#header-3)如何进入系统态？

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
   
本篇文章将会主要分析驱动程序、内核扩展模块中隐藏的提权漏洞

(暂未更新)