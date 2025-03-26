#### 功能说明

1. **漏洞库升级**：首先，使用`kylinos-patch.py`从`Kylin OS`官方网站抓取最新的漏洞公告，将清洗后的数据（公告 ID、级别、描述、发布时间、受影响的软件包、软件包修复版本、修复方法、软件包下载地址）存储到`kylinos_patch.xlsx`文件中，定期将excel文件转发到内网，完成漏洞信息更新。

2. **基线扫描**：使用`/lib/engine/scanner.py`中的ssh登录获取远程主机的已安装软件包，并根据匹配策略筛选出存在问题的软件包，和对应的风险，缺陷名，详细，解决方案，存储到`result.xlsx`文件中。

3. **匹配策略**：已安装软件包前缀、CPU架构出现在安全漏洞信息里，且软件包名称小于（即数字字母顺序上早于）最新的修复补丁名称，就筛选出来。

   

#### 部署

1. **扫描对象**：目前系统地址和账号密码硬编码在`kylinos_scan.py`里，直接修改即可。
2. **运行方式**：下载python库、python3.8执行、-h查看命令


