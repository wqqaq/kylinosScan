import sqlite3


class DatabaseManager:
    def __init__(self, db_name):
        """
        初始化 DatabaseManager 类。
        :param db_name: 数据库名称
        """
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        """
        创建 vulns 表，如果表不存在。
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY,
                公告_ID UNIQUE,
                安全级别 TEXT,
                描述 UNIQUE,
                发布时间 TEXT,
                详细介绍 TEXT,
                修复的CVE TEXT,
                受影响的软件包 TEXT,
                软件包修复版本 TEXT,
                修复方法 TEXT,
                软件包下载地址 TEXT
            )
        ''')
        self.conn.commit()

    def add_vuln(self, 公告_ID, 安全级别, 描述, 发布时间, 详细介绍, 修复的CVE, 受影响的软件包, 软件包修复版本, 修复方法, 软件包下载地址):
        """
        向 vulns 表中添加漏洞信息。
        :param 公告_ID: 公告 ID
        :param 安全级别: 安全级别
        :param 描述: 描述信息
        :param 发布时间: 发布时间
        :param 详细介绍: 详细介绍信息
        :param 修复的CVE: 修复的 CVE 信息
        :param 受影响的软件包: 受影响的软件包信息
        :param 软件包修复版本: 软件包修复版本信息
        :param 修复方法: 修复方法信息
        :param 软件包下载地址: 软件包下载地址信息
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO vulns (公告_ID, 安全级别, 描述, 发布时间, 详细介绍, 修复的CVE, 受影响的软件包, 软件包修复版本, 修复方法, 软件包下载地址)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (公告_ID, 安全级别, 描述, 发布时间, 详细介绍, 修复的CVE, 受影响的软件包, 软件包修复版本, 修复方法, 软件包下载地址))
        self.conn.commit()

    def get_vulns(self):
        """
        从 vulns 表中获取所有漏洞信息。
        :return: 包含所有漏洞信息的列表
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM vulns')
        return cursor.fetchall()

    def close(self):
        """
        关闭数据库连接。
        """
        self.conn.close()
