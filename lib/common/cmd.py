import argparse
import os
import sys
from lib.config import DEFAULT_PORT
from lib.common.log import creatLog

class CommandLines:
    def __init__(self):
        """
        初始化 CommandLines 类。
        解析命令行参数并存储相关信息，如静默模式、本地文件列表、IP 地址、端口、用户名、密码和系统版本。
        若提供了本地文件列表，将其转换为绝对路径。
        若未提供 IP 地址、端口、用户名、密码或系统版本，将其设置为 None 或默认值。
        """
        self.cmd = self.parse_arguments()
        self.cmd.silent = None
        self.log = creatLog().get_logger()

    def parse_arguments(self):
        """
        解析命令行参数。
        创建一个 ArgumentParser 对象，添加不同组的参数，包括必选参数、目标系统类型的数据库参数和身份配置参数。
        若未提供本地文件列表和 IP 地址，打印帮助信息并退出程序。
        :return: 解析后的命令行参数
        """
        parser = argparse.ArgumentParser(description='Script to perform CVE query and generate a report.')
        mandatory = parser.add_argument_group('Mandatory')
        mandatory.add_argument('-l', '--local_list', help='Local file path to extract outputs if SSH login fails')
        mandatory.add_argument('-i', '--ip', required=False, help='IP address of the remote server')

        data = parser.add_argument_group('Defect Database of Target System Types')
        data.add_argument('--release', choices=['V4', 'V6', 'V7', 'Host', 'SP1', 'SP2', 'SP3', 'HPC', 'KRB5'],
                            help='Specify the Kylin OS release for Accelerated Queries,default as Kylin V10SP2')

        identity = parser.add_argument_group('Identity Configuration')
        identity.add_argument('-P', '--port', default=DEFAULT_PORT, help='Port number for the remote server (default is 22)')
        identity.add_argument('-u', '--username', required=False, help='Username for the remote server')
        identity.add_argument('-p', '--password', required=False, help='Password for the remote server')


        args = parser.parse_args()

        if args.local_list == None and args.ip == None:
            args.print_help()
            sys.exit(0)
        return args

    def get_local_list(self):
        """
        获取本地文件列表。
        :return: 本地文件列表
        """
        return self.cmd.local_list

    def get_release(self):
        """
        获取系统版本。
        :return: 系统版本
        """
        return self.cmd.release

    def get_ip(self):
        """
        获取 IP 地址。
        :return: IP 地址
        """
        return self.cmd.ip

    def get_port(self):
        """
        获取端口号。
        :return: 端口号
        """
        return self.cmd.port

    def get_username(self):
        """
        获取用户名。
        :return: 用户名
        """
        return self.cmd.username

    def get_password(self):
        """
        获取密码。
        :return: 密码
        """
        return self.cmd.password

    def get_db_file(self):
        """
        根据系统版本获取数据库文件。
        :param package_release: 系统版本
        :return: 数据库文件路径
        """
        if self.cmd.release is None:
            print("Info: --release is None, using kylinVulnSP2.db by default.")
            return 'kylinVulnSP2.db'
        if self.cmd.release in ['SP2']:
            return 'kylinVulnSP2.db'
        if self.cmd.release in ['SP1', 'SP3', 'Host', 'V4', 'V6', 'V7', 'HPC', 'KRB5']:
            return 'kylinVuln.db'

    def get_kylinos_version(self, scanner):
        """
        获取 Kylin 操作系统的版本。
        执行 nkvers 命令并检查输出，调用 scanner 的 check_kylinos_version 方法。
        :param scanner: KylinOSScanner 对象
        :return: Kylin 操作系统的版本，如果出现异常返回 None
        """
        try:
            kylinos_commands = ["nkvers"]
            output = scanner.execute_commands(kylinos_commands)["nkvers"]
            if output:
                kylinos_version = scanner.check_kylinos_version(output)
                return kylinos_version
            return None
        except Exception as e:
            return None

    def get_package(self, scanner):
        """
        获取软件包信息。
        尝试执行 rpm -qa 命令获取软件包信息，若失败且存在本地文件列表，解析本地文件。
        :param scanner: KylinOSScanner 对象
        :return: 软件包信息，如果失败返回 None
        """
        try:
            kylinos_commands = ["rpm -qa"]
            output = scanner.execute_commands(kylinos_commands)["rpm -qa"]
            if isinstance(output, str):
                package_list = output.split('\n')
                return package_list
            else:
                return None
        except Exception as e:
            if self.cmd.local_list:
                output = self.parse_local_file(self.cmd.local_list)
                return output
            else:
                return None

    def parse_local_file(self, file):
        """
        解析本地文件。
        读取文件内容，将非空行添加到结果列表中，处理文件未找到和其他异常。
        :param file: 本地文件路径
        :return: 解析结果列表，如果出现异常返回 None
        """
        results = []
        try:
            with open(file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        results.append(line)
            return results
        except FileNotFoundError:
            self.log.debug(f"The file {file} was not found.")
            return None
        except Exception as e:
            self.log.error(f"An error occurred while parsing the local file: {e}")
            return None
