import pandas as pd
from lib.common.cmd import CommandLines
from lib.config import DEFAULT_KYLINV10SP2_DB
from lib.engine.scanner import KylinOSScanner
from lib.model.model import DatabaseHandler
from lib.controller.query import CVEQueryHandler
from lib.common.log import creatLog

class KylinProject:
    def __init__(self):
        """
        初始化 KylinProject 类。
        导入所需的配置对象，并进行一些初始化操作。
        """
        self.log = creatLog().get_logger()
        self.command_lines = CommandLines()
        self.kylinos_version = 'SP2'
        self.local_list = self.command_lines.get_local_list()
        self.packages = None
        self.ip_port = None
        self.db_file = DEFAULT_KYLINV10SP2_DB
        # self.utils = Utils()
        self.get_packages_and_ip_port()  # 格式化为列表
        self.db_file = self.command_lines.get_db_file()
        if self.packages and self.db_file:
            self.run()

    def get_packages_and_ip_port(self):
        """
        根据不同情况获取软件包列表和 IP 端口信息。
        """
        if self.local_list is None:
            ip = self.command_lines.get_ip()
            port = self.command_lines.get_port()
            self.ip_port = f"{ip}:{port}"
            username = self.command_lines.get_username()
            password = self.command_lines.get_password()
            scanner = KylinOSScanner(ip, port, username, password)
            self.kylinos_version = self.command_lines.get_kylinos_version(scanner)
            self.packages = self.command_lines.get_package(scanner)
        else:
            try:
                self.packages = self.command_lines.parse_local_file(self.local_list)
                if self.packages:
                    self.ip_port = '127.0.0.1:00'
                else:
                    self.log.debug("[*]No data to process from local file.")
                    exit(1)
            except Exception as e:
                self.log.error(f"[*]Error parsing local file: {e}")
                exit(1)

    def run(self):
        """
        运行主要的扫描和结果处理流程。
        """
        db_handler = DatabaseHandler(self.db_file)
        db_handler.initialize_databases()
        cve_query_handler = CVEQueryHandler(self.db_file, self.packages, self.kylinos_version, self.ip_port)
        queries = cve_query_handler.query_cve()
        data_list = [dict(zip(['Package', 'Risk', 'Vul', 'CVE_Id', 'CVE_Description', 'Solution', 'Impact Scope'], query)) for query in queries]
        df_result = pd.DataFrame(data_list, columns=['Package', 'Risk', 'Vul', 'CVE_Id', 'CVE_Description', 'Solution', 'Impact Scope'])
        writer = pd.ExcelWriter('result.xlsx', engine="xlsxwriter")
        df_result.to_excel(writer, 'sheet1', index=False)
        try:
            writer.save()
        except AttributeError:
            writer._save()
        if writer:
            self.log.info("[*]麒麟系统软件登录扫描完成，扫描文件 result.xlsx 已本地生成")
            self.log.debug('[*]请使用 Nessus 整理工具导入 result.xlsx，形成基线文档')
            self.log.warning('[*]请项目组检查缺陷影响的软件包多个安装版本的情况，低版本 rpm 包未清除会导致漏洞无法修复')

