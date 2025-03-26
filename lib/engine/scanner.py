import gc
import re
import paramiko
from packaging import version
from lib.model.database import DatabaseManager
from lib.common.log import creatLog

class KylinOSScanner:
    def __init__(self, hostname, port, username, password):
        """
        初始化 KylinOSScanner 类。
        :param hostname: 主机名
        :param port: 端口号
        :param username: 用户名
        :param password: 密码
        """
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.ssh = None
        self.log = creatLog().get_logger()
        self.login()

    def login(self):
        """
        尝试使用提供的凭证登录 SSH。
        处理可能出现的异常，如认证失败、连接失败等。
        """
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname=self.hostname, port=self.port, username=self.username, password=self.password)
            self.log.info('SSH登录成功')
        except paramiko.AuthenticationException:
            self.log.error('认证失败，请检查你的SSH凭证')
        except paramiko.SSHException:
            self.log.error('无法建立SSH连接')
        except Exception as e:
            self.log.error(f'SSH登录失败: {e}')


    def execute_commands(self, commands):
        """
        执行一系列命令并存储结果。
        :param commands: 命令列表
        :return: 存储命令结果的字典
        """
        results = {}
        if self.ssh:
            for command in commands:
                stdin, stdout, stderr = self.ssh.exec_command(command)
                # 等待命令执行完成
                stdout.channel.recv_exit_status()
                results[command] = stdout.read().decode().strip()
        return results

    def check_kylinos_version(self, output):
        """
        检查输出中是否包含特定的 Kylin 系统版本信息。
        :param output: 要检查的输出内容
        :return: 检测到的 Kylin 系统版本
        """
        releases = ['V4', 'V6', 'V7', 'Host', 'SP1', 'SP2', 'SP3', 'HPC', 'KRB5']
        package_release = None
        for release in releases:
            if release in output:
                package_release = release
                print(f'The remote server is Kylin system, the specific version is {package_release}')
        return package_release

    def packages_address_extract(self, text, architecture_suffixes):
        """
        从文本中提取包的名称。
        :param text: 包含包信息的文本
        :param architecture_suffixes: 架构后缀列表
        :return: 提取出的包名称列表
        """
        urls = text.split('\n')
        package_names = []
        for url in urls:
            for suffix in architecture_suffixes:
                if suffix in url:
                    last_slash_index = url.rfind('/')
                    suffix_index = url.rfind(suffix)
                    if last_slash_index!= -1 and suffix_index!= -1 and last_slash_index < suffix_index:
                        package_name = url[last_slash_index + 1:suffix_index]
                        package_names.append(package_name)
        return package_names

    def packages_prefix_extract(self, text):
        """
        提取包的前缀。
        :param text: 包的名称或信息
        :return: 提取出的包前缀
        """
        try:
            text_split = text.split('-')
            if text_split[1] in str(text_split[2:]):
                text = text_split[0] + '-' + ''.join(text_split[1:])
        except:
            pass
        match = re.search(r'(.*?)[-_](?=\d)', text)
        if match:
            return match.group(1)
        return None

    def extract_kve(self, description):
        """
        从描述中提取 CVE 或 KVE 信息。
        :param description: 描述信息
        :return: 提取出的 CVE 或 KVE 标识符和剩余的描述信息
        """
        try:
            description = description.strip().replace('\n', '')
            if 'CVE-' in description:
                pattern = r'CVE-\d{4}-\d{4,8}'
            elif 'KVE-' in description:
                pattern = r'KVE-\d{4}-\d{4,8}'
            else:
                return None, description
            matches = re.search(pattern, description)
            cve_id = matches.group(0)
            cve_description = description.split(cve_id)[1]
        except Exception as e:
            self.log.error(f"extract_kve error: {e}")
            return None, None
        return cve_id, cve_description

    def version_comparison(self, db_file, package, ip_port):
        """
        比较补丁版本，检查是否存在漏洞。
        :param db_file: 数据库文件
        :param package: 要检查的软件包
        :param ip_port: IP 端口信息
        :return: 包含包、风险、漏洞、CVE 标识符、CVE 描述、解决方案和 IP 端口的元组
        """
        architecture_suffixes = ['.x86_64', '.aarch64', '.mips64el', '.loongarch64', '.noarch', '_amd64', '_mips64el',
                             '_loongarch64', '_all']
        db_manager = DatabaseManager(db_file)
        rows = db_manager.get_vulns()
        for row in rows.iterrows():
            risk = row[2]
            vul = row[3]
            description = row[6]
            fixed_package_suffix = str(row[8])
            solution = str(row[10])
            package_suffix = ''
            package_name = ''
            Fixed_packages = self.packages_address_extract(solution, architecture_suffixes)
            for suffix in architecture_suffixes:
                if package.endswith(suffix):
                    package_name = package.replace(suffix, '').split()[0]  # 当前包 libfastjson-0.99.9-3.ky10
                    package_suffix = suffix.replace('.', '')
            package_prefix = self.packages_prefix_extract(package)

            if package_suffix in fixed_package_suffix and package_prefix in solution:
                for Fixed_package in Fixed_packages:
                    if package_prefix == self.packages_prefix_extract(Fixed_package):
                        if version.parse(package_name) < version.parse(Fixed_package):
                            while True:
                                cve_id, cve_description = self.extract_kve(description)
                                if cve_id is None:
                                    break
                                else:
                                    return package, risk, vul, cve_id, cve_description, solution, ip_port
        db_manager.close()
        gc.collect()
        return False
