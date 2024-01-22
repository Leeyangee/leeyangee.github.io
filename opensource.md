---
layout: page
title: 开源工作
---

# [](#header-1)bugctf
基本语言: Python3  
最新版本: 1.1.2  

bugctf是一个小型的基于python3.6的包，自leectf项目改进而来，由suse_bug团队共同开发.  
其包含了多种论证完善的CTF常见算法、数据可视化API、配套的完整方法注释，目的是把用户从CTF和Web实战中重复造轮子的过程抽离，为各类渗透活动、攻防演练行动提供通用安全解决方案.  

<details>
      <summary><font color="#2bbc8a">生成二阶希尔伯特曲线:</font></summary>
      <pre><code>
>>> import bugctf
>>> bugctf.algo.hilbert(2)
[(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3), (1, 3), (1, 2), (2, 2), (2, 3), (3, 3), (3, 2), (3, 1), (2, 1), (2, 0), (3, 0)]
      </code></pre>
</details><p></p>

<details>
      <summary><font color="#2bbc8a">快速比对以查找通用web资产的特征及指纹:</font></summary>
      <pre><code>
>>> import bugctf
>>> bugctf.net.findFingerprint(["https://www.baidu.com","https://110.242.68.3",...])
['https://pss.bdstatic.com/static/superman/img/logo/bd_logo1-66368c33f8.png',...]
      </code></pre>
</details><p></p>

<details>
      <summary><font color="#2bbc8a">绘制黑白像素图:</font></summary>
      <pre><code>
>>> import bugctf
>>> bugctf.plot.pts_to_2DPixel([[1,1],[2,3],[4,2]])
      </code></pre>
</details><p></p>


pip安装(暂不可用): `pip3 install bugctf`  
