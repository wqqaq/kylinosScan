import os
import sqlite3
import pandas as pd

from lib.common.log import creatLog
from lib.model.database import DatabaseManager
from lib.config import DEFAULT_KVE_EXCEL_FILE, DEFAULT_KYLINV10SP2_EXCEL_FILE


class DatabaseHandler:
    def __init__(self, db_file):
        self.db_file = db_file
        self.log = creatLog().get_logger()
        self.db_manager = DatabaseManager(db_file)

    def transfer_excel_to_sqlite(self, excel_file, db_manager):
        """
        将 Excel 文件的数据转移到 SQLite 数据库。

        参数:
        excel_file (str): Excel 文件的路径。
        db_manager (DatabaseManager): 数据库管理器对象。
        """
        df = pd.read_excel(excel_file, header=0, keep_default_na=False, engine='openpyxl')
        for index, row in df.iterrows():
            try:
                db_manager.add_vuln(
                    公告_ID=row['公告 ID'],
                    安全级别=row['安全级别'],
                    描述=row['描述'],
                    发布时间=row['发布时间'],
                    详细介绍=row['详细介绍'],
                    修复的CVE=row['修复的CVE'],
                    受影响的软件包=row['受影响的软件包'],
                    软件包修复版本=row['软件包修复版本'],
                    修复方法=row['修复方法'],
                    软件包下载地址=row['软件包下载地址']
                )
            except sqlite3.IntegrityError:
                pass

    def initialize_databases(self):
        """
        初始化数据库，将 Excel 文件中的数据转移到 SQLite 数据库中。
        """
        self.initialize_database('kylinVuln.db', DEFAULT_KVE_EXCEL_FILE)
        self.initialize_database('kylinVulnSP2.db', DEFAULT_KYLINV10SP2_EXCEL_FILE)


    def initialize_database(self, db_file, excel_file):
        """
        初始化数据库，如果数据库文件不存在则创建并转移 Excel 数据。

        参数:
        db_file (str): 数据库文件的路径。
        excel_file (str): Excel 文件的路径。
        """
        if not os.path.exists(db_file):
            self.log.info(f"数据库文件 {db_file} 不存在，初始化中......")
            db_manager = DatabaseManager(db_file)
            self.transfer_excel_to_sqlite(excel_file, db_manager)
            db_manager.close()