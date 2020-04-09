注意事项：
-------------
- Sample.java 提供了示例以供开发者参考。
- com\fmtech\encrypt目录中的文件是实现加解密的业务逻辑类。
- EncryptorLogic.java 类提供了 encrypt 和 decrypt 方法，分别用于对消息的加密、解密功能。
- ResponseData.java 类定义了加密后返回的数据结构。
- 使用方法可以参考Sample.java文件。
- 加解密方案请参考《枫芒BOSS系统API调试手册》。

**请特别注意**

异常java.security.InvalidKeyException:illegal Key Size的解决方案（JDK8+以上没有这个问题）：

在官方网站下载JCE无限制权限策略文件（JDK7的下载地址：
http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html）下载后解压，可以看到local_policy.jar和US_export_policy.jar以及readme.txt。

如果安装了JRE，将两个jar文件放到%JRE_HOME%\lib\security目录下覆盖原来的文件，

如果安装了JDK，将两个jar文件放到%JDK_HOME%\jre\lib\security目录下覆盖原来文件