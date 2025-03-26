import subprocess
import pkg_resources
import sys
import os


class LibraryManager:
    def __init__(self, required_libraries):
        """
        初始化 LibraryManager 类。

        参数:
        required_libraries (dict): 包含所需库及其版本要求的字典。
        """
        self.required_libraries = required_libraries

    def check_and_install(self):
        """
        检查所需库是否已安装并满足版本要求，若未安装或版本不满足则进行安装或升级。
        """
        for lib, version in self.required_libraries.items():
            try:
                installed_version = pkg_resources.get_distribution(lib).version
            except pkg_resources.DistributionNotFound:
                print(f"{lib} is not installed.\nRunning the installation script.")
                self._run_install_script(lib)
            else:
                if pkg_resources.parse_version(installed_version) < pkg_resources.parse_version(version):
                    print(f"{lib} version {version} or higher is required. Upgrading...")
                    self._run_install_script(lib)

    def _run_install_script(self, lib):
        """
        运行库的安装脚本。

        参数:
        lib (str): 要安装的库的名称。
        """
        install_script = "build\\install.bat"
        subprocess.run(['cmd.exe', '/c', install_script], check=True)


class MainProgram:
    def __init__(self):
        """
        初始化 MainProgram 类。
        """
        self.required_libraries = {
            'pandas': '>=1.1.5',
            'paramiko': '>=2.7.2',
            'packaging': '=21.0',
            'openpyxl': '>=3.4.0',
        }
        self.library_manager = LibraryManager(self.required_libraries)

    def run(self):
        """
        运行主程序，包括检查和安装所需库，banner展示,以及调用 kylin_controller 的 main 函数。
        """

        if sys.version_info < (3, 0):
            sys.stdout.write("Sorry, scanner requires Python3.x \n")
            sys.exit(1)
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'lib')))
        self.library_manager.check_and_install()
        from lib.common.banner import RandomBanner
        RandomBanner()
        from lib.controller.controller import KylinProject
        KylinProject()


if __name__ == '__main__':
    main_program = MainProgram()
    main_program.run()
