---
title: Apache Geode 审计现场实战 - 漏洞链构造/实时更新
published: true
---

这段时间笔者准备重新审计在此之前遇到的一个 Apache 中间件，并且会在这里实时开源自己新鲜审计出来的利用链，供读者学习  

如果有人利用笔者的思路/利用链比我先审出来RCE也没关系，这篇文章提到的利用链都是完全开放的  
如果没审出来 RCE 也没关系，至少能学习到最优秀的程序员 coding 风格、审计思路和得到一堆本地命令执行漏洞  

Apache Geode 介绍：  
Apache Geode 是一个基于 JVM 的 NoSQL 分布式数据处理平台，提供实时的、一致的、贯穿整个云架构地访问数据关键型应用，他的特点是强一致性和高实时性、对数据结构有更强的表达能力，能描述部分逻辑表达的内存数据库  
Apache Geode 的官方网站：[https://geode.apache.org/](https://geode.apache.org/)  

# [](#header-31)利用链 1: CacheServerHelper.deserialize(Args)

在 org.apache.geode.inte

由于今天太晚了，明天再更新
