致远OA代码审计系列一
===========

原创 作者:archive 公号:安全回忆录 发布时间:2023-11-28 7:01 发表于北京

原文地址：[致远OA代码审计系列一](https://mp.weixin.qq.com/s/TjKLMesbRCry7Tk8k8kjYA)

**前言**

致远OA是致远云技术变革诞生的新一代“互联网云协同”的行业协同云产品。深耕行业领域，提供符合行业特性的企业管理应用及产品，并以“流程、数据、云技术、移动、业务定制技术”为核心，打造云端的一站式、可定制的行业协同工作平台。成为多行业的中小微企业客户的团队管理和工作的新方式。

致远OA作为国内头部OA系统, 历史上出现众多的安全漏洞, 也是每年大小HW的重点攻击对象. 这个系列将全方面的分析致远OA历史漏洞以及部分官方已经修复但无细节的相关漏洞. 这一章节主要介绍致远OA审计环境搭建以及致远OA路由、权限绕过的相关思路。

**环境安装**

```makefile
致远OA版本: V8.1 SP1
系统: Windows 2008
授权: 测试授权(破解补丁)
```

致远各个版本间漏洞存在差异, 这里选择V8.1 SP1进行审计, 其余版本后续文章会补充。

数据库安装踩坑记录:

```sql
Ø 数据引擎要求为InnoDB
检查MySQL配置文件的[mysqld]项中default-storage-engine值，检查是否为InnoDB，若不是则调整为InnoDB。
Ø 字符集要求为utf8
检查MySQL配置文件的[client]、[mysql]项中default-character-set值，以及[mysqld]项中character-set-server（或default-character-set）值，检查是否为utf8，若不是则调整为utf8。
Ø 要求不区分表/字段大小写
检查MySQL配置文件的[mysqld]项中是否包含lower_case_table_names=1，不包含则添加，包含则保证其值为1。
Ø wait_timeout=28800
```

数据库配置完成后. 双击SeeyonA8-1Install.bat正常安装, 安装完成后在startup.bat中配置远程debug, 如果是采用云主机进行的远程安装degub, 切记安全组设置相关ACL组策略. 避免出现JDWP远程代码执行漏洞. 特别提一下, 在各类红蓝对抗演练中可以特别关注下JDWP, RMI等服务端口. 内外网都能遇到。在startup.bat中添加:  

```sql
SET CATALINA_OPTS=-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=12344
```

初次登陆后需要进行相关配置, 添加组织, 管理员等. 正常配置即可  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icjoOlvoibkRsLOlZvYHZiaySWD9MZVKrb2OlYJ4RzkX7p3c8OvlQmtgwg/640?wx_fmt=png&from=appmsg)

IDEA配置远程debug,即可开始代码审计.   

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2ic1pqk5ePHqtkibKY9HOPLPtpTyPiacjGIBu7ibRW3yjicljjn9eEKumGmuA/640?wx_fmt=png&from=appmsg)

**路由分析**  

致远OA 的核心路由配置在/ApacheJetspeed/webapps/seeyon/WEB-INF/web.xml中. 路由主要为Servlet、spring controller、REST Web Service、JSP. 其中Servlet在web.xml中即可查看, controller对应的路由可以通过ApacheJetspeed/webapps/seeyon/WEB-INF/cfgHome/spring下的xml配置文件查看路由对应关系. REST Web Service可以通过/REST/\*或/webOffice/\*进行访问。  

**权限分析**

致远OA主要权限校验部分在CTPSecurityFilter过滤器中, 其将所有的url请求分为了7类。

```typescript
    private static boolean isSpringController(String uri, HttpServletRequest request) {
        boolean result = uri.endsWith(".do");
        return !result && uri.indexOf(".do;jsessionid=") > 0 ? true : result;
    }


    private static boolean isAjax(String uri, HttpServletRequest request) {
        return uri.endsWith("ajax.do");
    }


    private static boolean isV3xAjax(String uri, HttpServletRequest request) {
        return uri.endsWith("getAjaxDataServlet");
    }


    private static boolean isRest(String uri, HttpServletRequest request) {
        return uri.startsWith(request.getContextPath() + "/rest/");
    }


    private static boolean isSOAP(String uri, HttpServletRequest request) {
        return uri.startsWith(request.getContextPath() + "/services/");
    }


    private static boolean isServlet(String uri, HttpServletRequest request) {
        return ServletAuthenticator.accept(request);
    }


    private static boolean isJSP(String uri, HttpServletRequest request) {
        if (uri == null) {
            return false;
        } else {
            String lowUri = uri.toLowerCase();
            return lowUri.endsWith(".jsp") || lowUri.endsWith(".jspa") || lowUri.endsWith(".jsw") || lowUri.endsWith(".jsv") || lowUri.endsWith(".jtml") || lowUri.endsWith(".jspf") || lowUri.endsWith(".jhtml");
        }
    }
```

1.  `isSpringController`方法：
    

*   判断是否为Spring Controller.如果URI以".do" 结尾或者包含".do;jsessionid="，则为Spring Controller请求。
    
*   返回值:如果是SpringController，返回`true`。
    

3.  `isAjax`方法：
    

*   判断是否为Ajax请求。如果URI以"ajax.do"结尾，则为Ajax请求。
    
*   返回值:如果是Ajax请求,返回`true`。
    

5.  `isV3xAjax` 方法：
    

*   判断是否为V3xAjax请求。如果URI以"getAjaxDataServlet"结尾，则为V3xAjax请求。
    
*   返回值:如果是V3xAjax请求,返回`true`。
    

7.  `isRest` 方法：
    

*   判断是否为RESTful请求。如果URI以"/rest/"开头,则为RESTful请求。
    
*   返回值：如果是RESTful请求,返回`true`。
    

9.  `isSOAP`方法：
    

*   判断是否为SOAP请求,如果URI以"/services/"开头,则为SOAP请求。
    
*   返回值:如果是SOAP请求,返回`true;`
    

11.  `isServlet`方法：
    

*   判断是否为Servlet请求。
    
*   返回值:如果是Servlet请求,返回`true.`
    

13.  `isJSP`方法：
    

*   判断是否为JSP 请求。如果URI以一系列指定的JSP文件后缀结尾(如 ".jsp", ".jspa" 等),则为 JSP 请求。
    
*   返回值:如果是 JSP 请求,返回`true.`
    

针对不同类型的URL, 致远OA会根据不同的类型设置不同的Authenticator进行权限校验。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icXMblhMgVXfr2DnBNKe6xf4uboYYUOMUg9ibYibHpj2ojSfjXGlDiaBiaqg/640?wx_fmt=png&from=appmsg)

如果不是以上7种类型, 则会调用默认的defaultAuthenticator。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icBgOL2SWOnRvnWqIVCtSrBVZVbau40QrYoIKyYYljDJtRg8uqnrZT0g/640?wx_fmt=png&from=appmsg)

defaultAuthenticator的authenticate方法中仅进行了uri.startsWith()判断, 所以只要咱们访问的路径没在以上7个判断类型中, 进入到defaultAuthenticator即可通过致远OA的权限校验。

针对不同的URL类型. 不同的认证器分别为:

**isSpringController**: uri为.do结尾或者存在.do;jsessionid=

```typescript
private static boolean isSpringController(String uri, HttpServletRequest request) {
        boolean result = uri.endsWith(".do");
        return !result && uri.indexOf(".do;jsessionid=") > 0 ? true : result;
    }
```

在SpringControllerAuthenticator的authenticate中, 当user为null的时候会判断当前路径是否在白名单中, 跟进isNeedlessCheckLogin函数。

```kotlin
if (user == null) {
  AppContext.removeThreadContext("SESSION_CONTEXT_USERINFO_KEY");
  isAnnotationNeedlessLogin = this.isNeedlessCheckLogin(context);
  LoginTokenUtil.checkLoginToken(request);
  if (!isAnnotationNeedlessLogin) {
      isAnnotationNeedlessLogin = this.isSocialAuth(request, context);
  }
}
```

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icIHGFfxCmgcRRkmGSfXEzKGHjiaiaaqzeZXc7EBI2OH2ZEW5yMWpC7CWg/640?wx_fmt=png&from=appmsg)

其中的needlessUrlMap在initNeedlessLoginBeans中进行初始化. 具体配置在needless\_check\_login.xml中. 在needless\_check\_login.xml中的白名单即可通过当前SpringControllerAuthenticator的认证。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2iczACzvh96q8meQh57o2icXtqXianyHDmaWy0gbcFMXXiam8e6jiaq9xAuBA/640?wx_fmt=png&from=appmsg)

当前版本存在36个白名单Controller可以直接调用. 如果不在needless\_check\_login.xml白名单内, 还会进行isSocialAutha判断. 检查当前请求是否是社交认证。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2iccVSB4nU9Rk5BnalibmJl9IztWPAff6CJTmiciaDXK8MqSia0kiaDndIP4BQ/640?wx_fmt=png&from=appmsg)

遍历socialUrls映射，检查当前请求的路径是否包含在映射中，并且请求的方法是否包含在映射中。socialUrls在静态代码中被初始化。

```javascript
 static {
        socialUrls.put("/wechat/feishu.do", new HashSet(Arrays.asList("newMain", "viewh5Message")));
        socialUrls.put("/wechat/pcapp.do", new HashSet(Arrays.asList("transferPageFromWxCoreServer", "gotoPcApp")));
        socialUrls.put("/wechat/feishu/approvalData.do", new HashSet(Arrays.asList("index")));
        socialUrls.put("/zhifei/feishu.do", new HashSet(Arrays.asList("newMain", "viewh5Message")));
        socialUrls.put("/zhifei/pcapp.do", new HashSet(Arrays.asList("transferPageFromWxCoreServer", "gotoPcApp")));
        socialUrls.put("/zhifei/feishu/approvalData.do", new HashSet(Arrays.asList("index")));
    }
}
```

在socialUrls和needless\_check\_login.xml白名单中的url在SpringControllerAuthenticator的认证器中可以认证通过, 无需登陆。

**isAjax**: ajax.do结尾

```typescript
private static boolean isAjax(String uri, HttpServletRequest request) {
        return uri.endsWith("ajax.do");
    }
```

AjaxAuthenticator的authenticate方法中对managerName和methodName进行了一定的限制. 其他的和isSpringController中的一致, 需要为needless\_check\_login.xml白名单即可通过验证。

**isRest**: startsWith /rest/开头

```typescript
private static boolean isRest(String uri, HttpServletRequest request) {
        return uri.startsWith(request.getContextPath() + "/rest/");
    }
```

RestAuthenticator验证器中的authenticate方法中, 通过isIgnoreToken判断是否在匿名白名单中, 在白名单中即可通过验证。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icia997g42WVnG5aXRerAJhRGC0DmANuZpv5VMVBxmia9icmibMg2s9jhcNw/640?wx_fmt=png&from=appmsg)

```typescript
    protected boolean isIgnoreToken(String path) {
        Iterator var2 = anonymousWhiteList.iterator();


        String string;
        do {
            if (!var2.hasNext()) {
                return false;
            }


            string = (String)var2.next();
            if (string.equals(path)) {
                return true;
            }
        } while(!path.startsWith(string));


        return true;
    }

```

匿名白名单在静态代码块中初始化。  

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
        anonymousWhiteList = Arrays.asList("token", "application.wadl", "jssdk", "getRestCompare", "authentication", "cap4/form/pluginScripts", "orgMember/avatar", "orgMember/groupavatar", "m3/appManager/getAppList", "m3/appManager/download", "m3/message/unreadCount/", "m3/login/refresh", "m3/login/verification", "m3/theme/homeSkin", "m3/theme/homeSkinDownload", "m3/common/service/enabled", "uc/systemConfig", "product/hasPlugin", "product/dongle/data", "password/retrieve", "m3/appManager/checkEnv", "m3/security/device/apply", "meeting/meetingInviteCard", "microservice", "media/verify", "ocip/forwardTo");
        guestWhiteList = Arrays.asList("webOffice/checkWebOfficeEnable", "webOffice/getBookMarkUpdateFlag", "webOfficeTrans/buildWebOfficeParams");
        visitorWhiteList = Arrays.asList("publicQrCode", "attachment", "commonImage", "m3/common/getConfigInfo", "meeting", "cmpNews", "doc");
    }
```

在anonymousWhiteList列表匿名白名单中的路径可以访问,通过认证器。

**isV3xAjax:** endWith("getAjaxDataServlet")

```typescript
private static boolean isV3xAjax(String uri, HttpServletRequest request) {
        return uri.endsWith("getAjaxDataServlet");
    }

```

getAjaxDataServlet在web.xml中有对应的Servlet, 可通过反射调用部分类和方法,后续在漏洞分析部分会提到. 在V3xAjaxAuthenticator的authenticate方法中, 通过needCheckLogin方法判断调用的serviceName和methodName是否需要登陆。  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icjcOL9a366rYrKU28IiaAUD0SNywUuyicRTQgOaUlGYd2wLmZRb0EMJfw/640?wx_fmt=png&from=appmsg)

在白名单中的ServiceName和methodName可以通过这个认证器.   

```typescript
    private boolean needCheckLogin(String serviceName, String methodName) {
        if (serviceName != null && methodName != null) {
            return !WHITE_LIST.contains(serviceName.trim() + "_" + methodName.trim());
        } else {
            return false;
        }
    }
```

WHITE\_LIST为静态常量集合, 只要在WHITE\_LIST中的ServiceName和methodName即可通过。

```javascript
private static final Set<String> WHITE_LIST = new HashSet(Arrays.asList("ajaxColManager_colDelLock", "ajaxEdocSummaryManager_deleteUpdateObj", "ajaxEdocManager_ajaxCheckNodeHasExchangeType", "ajaxEdocSummaryManager_deleteUpdateRecieveObj"));

```

  

**isSOAP:** startWith("/services/")

```typescript
private static boolean isSOAP(String uri, HttpServletRequest request) {
        return uri.startsWith(request.getContextPath() + "/services/");
    }
```

SOAPAuthenticator中的authenticate没有任何的校验, 直接返回ture. 但web.xml中对应的servlet(CtpAxis2Servlet)默认未注册任何service。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icT38lB2lb69wPO0mIkAuLhxALpftIJUPxtNbmKTTHa6FYFz72d4SQfA/640?wx_fmt=png&from=appmsg)

**isServlet:**  

```typescript
private static boolean isServlet(String uri, HttpServletRequest request) {
        return ServletAuthenticator.accept(request);
    }
```

psml结尾的请求和在servlets列表中的请求均返回true,servlets集合为静态变量。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icVYFENyJLKzNpA47LPiaH4T3RUSNUhIRJmGvcLPevgibwI7mY6D6vYHXw/640?wx_fmt=png&from=appmsg)

```typescript
 private static List<String> servlets = Arrays.asList("getAJAXMessageServlet", "getAJAXOnlineServlet", "htmlofficeservlet", "isignaturehtmlH5servlet", "isignaturehtmlservlet", "login/sso", "login/ssologout", "m-signature/", "ofdServlet", "office/cache/", "officeservlet", "pdfservlet", "sursenServlet", "verifyCodeImage.jpg");
 private static List<String> anonymousWhiteList = Arrays.asList("login/sso", "verifyCodeImage.jpg", "getAJAXOnlineServlet");

```

但是这里存在一个问题, 静态变量servlets列表中的servlet列表远比web.xml中定义的少很多. 这也导致了后续的一些漏洞问题。

ServletAuthenticator的authenticate方法, 在anonymousWhiteList匿名白名单列表中的路径可以通过该认证器。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2ic5FXTOrtKO2cHrQDyCtY7Fff8cZMiaEjKUg9dibMbVib8babIBk0Yagz3g/640?wx_fmt=png&from=appmsg)

**isJsp:**  

```typescript
private static boolean isJSP(String uri, HttpServletRequest request) {
        if (uri == null) {
            return false;
        } else {
            String lowUri = uri.toLowerCase();
            return lowUri.endsWith(".jsp") || lowUri.endsWith(".jspa") || lowUri.endsWith(".jsw") || lowUri.endsWith(".jsv") || lowUri.endsWith(".jtml") || lowUri.endsWith(".jspf") || lowUri.endsWith(".jhtml");
        }
    }
```

JSPAuthenticator的authenticate方法中, 在anonymouswhiteList白名单中的JSP文件可以直接访问, 但是还有一个条件.  JSPAuthenticator初始化时会去加载/ApacheJetspeed/webapps/seeyon/WEB-INF/cfgHome/security/路径下以 "jsp\_whitelist\_" 开头的文件, 如果存在则将规则和文件的最后修改时间添加到 JSP\_WHITELIST 中。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icZgsfLTGBGjC7c1VEAic2GeVtA0cBIR6Y68OaePDye2lgRuJvUo4DtaA/640?wx_fmt=png&from=appmsg)

在authenticate方法中, 会对jsp文件进行一次判断, 当修改时间能晚于启动时间会抛出错误, 防止jsp文件被篡改,时间正常且在白名单内即可正常访问。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuzdKfsfdT72FmPcV6TlP2icDLTcS5agfP1A0FkZSSmQLRG0QAqcs6Zw2EbyEItJwKbwibNIkIicOic3Q/640?wx_fmt=png&from=appmsg)

除了以上7个判断, 还存在两个类型的判断:   

```javascript
else if (tokenAuthenticator.validate(uri, req)) {
  result.setAuthenticator(tokenAuthenticator);
  result.authenticate(req, resp);
} 
else if (webOfficeAuthenticator.validate(uri, req)) {
  result.setAuthenticator(webOfficeAuthenticator);
  result.authenticate(req, resp);
}
```

tokenAuthenticator: 

```kotlin
public boolean validate(String uri, HttpServletRequest req) {
    if (req.getParameter("tko") == null) {
        return false;
    } else if (req.getParameter("m") == null) {
        return false;
    } else if (req.getParameter("m").equals("k") && req.getAttribute("controllerValidateSuccess") == null) {
        return false;
    } else if (req.getParameter("m").equals("u") && req.getAttribute("controllerValidateSuccess") == null) {
        return false;
    } else {
        return !req.getParameter("m").equals("s") || validUriList.contains(uri.substring(uri.lastIndexOf("/")));
    }
}
```

当存在tko以及m参数且不等于s或者路径为wpsAssistServlet的时. 采用的TokenAuthenticator认证器. 

webOfficeAuthenticator:

```typescript
    public boolean validate(String uri, HttpServletRequest req) {
        Iterator var3 = validUriList.iterator();


        String validUri;
        do {
            if (!var3.hasNext()) {
                return false;
            }


            validUri = (String)var3.next();
        } while(!uri.startsWith(req.getContextPath() + validUri));


        return true;
    }
```

当uri以validUriList列表中的路径webOffice开头. 则进入webOfficeAuthenticator认证器

```php
private static final List<String> validUriList = Arrays.asList("/webOffice");
```

最后在提一下在CTPSecurityFilter中, 首先会进行isUnAttackUri判断, 该方法的作用就是判断请求是否是危险请求, 致远oa后面的一些权限绕过修复就是通过该方法进行修复. 请求Uri中不能出现("./", ";", ".jspx", ".##", "/##")

```typescript
private static boolean isUnAttackUri(String uri) {
        if (StringUtils.isBlank(uri)) {
            return true;
        } else {
            try {
                uri = URLDecoder.decode(uri, "UTF-8");
            } catch (UnsupportedEncodingException var4) {
                logger.error("", var4);
            }


            uri = uri.toLowerCase().replace(";jsessionid=", "##");
            List<String> attackStrList = Arrays.asList("./", ";", ".jspx", ".##", "/##");
            Iterator var2 = attackStrList.iterator();


            String attackStr;
            do {
                if (!var2.hasNext()) {
                    return true;
                }


                attackStr = (String)var2.next();
            } while(!uri.contains(attackStr));


            return false;
        }
    }
```

  

**总结:**

结合致远OA CTPSecurityFilter权限认证流程, CTPSecurityFilter中对不同的uri进行了分类, 并且不同类型的uri分别对应不同的认知器. 从权限绕过的维度可以从以下几个点进行思考: 

1.   如何让认证器走到defaultAuthenticator认证器?
    
2.  各个认证器的白名单路径方法是否存在利用可能?
    
3.  web.xml中的filter/servlet和CTPSecurityFilter中的差异是否存在利用可能?(是否有直接能利用的servlet/filter)
    
4.  几个if判断语句是否存在绕过?
    
5.  各个认证器是否存在绕过利用?
    

以上几个点在致远OA历史漏洞中均有出现过, 在下一篇致远OA代码审计系列会针对致远oa历史权限绕过漏洞进行分析. 并分享之前挖到的一些致远OA RCE的相关漏洞(现已修复)。