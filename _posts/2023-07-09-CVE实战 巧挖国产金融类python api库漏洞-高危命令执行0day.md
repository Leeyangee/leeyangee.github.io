---
title: CVE实战 巧挖国产金融类python api库漏洞-高危命令执行0day
published: true
---
# [](#header-1)0、前言  
这次是挖的比较顺利的一次，整个过程非常的舒服，写个博客记录一下  
这个1.8k的中等体量的国产开源项目犯了一些低级错误，让我在构造整个漏洞利用链的过程中，没有遇到全部从0开始的绝路  
当然，这次挖掘在代码绕过方面也走了一点弯路，浪费了不少时间，吸取一下教训  

复现：
至少需要装python3  
xalpha库可以从github上下载，但最好用pip3直接就能把库拉到本地  

由于这两天事情多，没时间写博客，恐怕只能先看github issue了  
https://github.com/refraction-ray/xalpha/issues/175  


