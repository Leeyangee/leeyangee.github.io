---
layout: page
title: 开源工作
---

# [](#header-1)leectf
基本语言: Python3  
最新版本: 1.1.0  

leectf是一个小型的基于python3.6的包，其包含了多种CTF常见算法及数据可视化API和配套的完整方法注释，专注于提升CTF和渗透实战的效率  

生成二阶希尔伯特曲线:  
```py
>>> import leectf
>>> leectf.algo.hilbert(2)
[(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3), (1, 3), (1, 2), (2, 2), (2, 3), (3, 3), (3, 2), (3, 1), (2, 1), (2, 0), (3, 0)]
```

快速比对以查找多个web资产特征及指纹:  
```py
>>> import leectf
>>> leectf.net.findFingerprint(["https://www.baidu.com","https://110.242.68.3",...])
['https://pss.bdstatic.com/static/superman/img/logo/bd_logo1-66368c33f8.png',...]
```

绘制黑白像素图:  
```py
>>> import leectf
>>> leectf.plot.draw2DPixel([[1,1],[2,3],[4,2]])
```

pip安装: <font color="red"></font>
