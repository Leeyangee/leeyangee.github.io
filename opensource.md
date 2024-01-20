---
layout: page
title: 开源工作
---

# [](#header-1)bugctf
基本语言: Python3  
最新版本: 1.1.0  

bugctf是一个小型的基于python3.6的包，由suse_bug团队共同开发，其包含了多种CTF常见算法及数据可视化API和配套的完整方法注释，专注于提升CTF和渗透实战的效率  

<details>
      <summary><font color="#2bbc8a">生成二阶希尔伯特曲线:</font></summary>
      <pre><code>
>>> import leectf
>>> leectf.algo.hilbert(2)
[(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3), (1, 3), (1, 2), (2, 2), (2, 3), (3, 3), (3, 2), (3, 1), (2, 1), (2, 0), (3, 0)]
      </code></pre>
</details><p></p>

<details>
      <summary><font color="#2bbc8a">快速比对以查找通用web资产的特征及指纹:</font></summary>
      <pre><code>
>>> import leectf
>>> leectf.net.findFingerprint(["https://www.baidu.com","https://110.242.68.3",...])
['https://pss.bdstatic.com/static/superman/img/logo/bd_logo1-66368c33f8.png',...]
      </code></pre>
</details><p></p>

<details>
      <summary><font color="#2bbc8a">绘制黑白像素图:</font></summary>
      <pre><code>
>>> import leectf
>>> leectf.plot.draw2DPixel([[1,1],[2,3],[4,2]])
      </code></pre>
</details><p></p>


pip安装: `pip3 install bugctf`  
<font color=FF0000>由于潜在的安全风险，该库已被pypi官方暂时重审</font>

