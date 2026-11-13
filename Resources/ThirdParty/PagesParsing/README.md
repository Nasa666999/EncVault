# 离线 Pages 正文解析组件

Mac 应用动态使用 libetonyek 0.1.13、librevenge 0.0.6 及 liblangtag 0.6.7。解析器与依赖随应用分发，运行时不使用 Homebrew、不下载组件、不启动 Pages 应用。当前本机架构构建的解析组件要求 macOS 26 及以上；更早的 Mac 系统使用系统文档预览。

- libetonyek：MPL 2.0。源码：https://dev-www.libreoffice.org/src/libetonyek/libetonyek-0.1.13.tar.xz ，SHA-256 `032b71cb597edd92a0b270b916188281bc35be55296b263f6817b29adbcb1709`。
- libetonyek 的 Homebrew 构建包含 mdds 兼容补丁：https://src.fedoraproject.org/rpms/libetonyek/raw/65a93fb7f21fb0e668d78644ec6aa7843e5372f5/f/mdds3.patch ，SHA-256 `cd390fa4280b78fd0d1a7f587ab576d8ef0c4848036c8b0c821b576c6745db17`。
- librevenge：可选 MPL 2.0 或 LGPL 2.1 及后续版本。源码：https://downloads.sourceforge.net/project/libwpd/librevenge/librevenge-0.0.6/librevenge-0.0.6.tar.xz ，SHA-256 `19eacf5ce55d7fe6a990a45142589cdf7da0c7b68701797f133482cb44f189fa`。
- liblangtag：LGPL 2.1 及后续版本。源码：https://bitbucket.org/tagoh/liblangtag/downloads/liblangtag-0.6.7.tar.bz2 ，SHA-256 `5ed6bcd4ae3f3c05c912e62f216cd1a44123846147f729a49fb5668da51e030e`。

以上组件的源代码未由应用修改；打包时仅调整动态库安装路径并与应用一起签名。MPL 与 LGPL 许可全文、上游作者清单随本目录分发。可从上述版本源码重新构建相应动态库，替换应用的 `Contents/Frameworks/PagesParsing` 后，将解析器、依赖和宿主重新签为同一身份；临时本机签名的打包入口使用 `Scripts/package-pages-reader.py`。
