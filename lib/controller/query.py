import gc
import re
from collections import defaultdict
from queue import Queue

from packaging import version

from lib.common.log import creatLog
from lib.model.database import DatabaseManager
from concurrent.futures import ThreadPoolExecutor, as_completed


class CVEQueryHandler:
    def __init__(self, db_file, packages, system_version, ip_port):
        self.db_file = db_file
        self.packages = packages   # 格式化为列表
        self.system_version = system_version
        self.ip_port = ip_port
        self.log = creatLog().get_logger()
        self.vulns = self._load_vulns()  # 预加载漏洞数据

    def _load_vulns(self):
        db_manager = DatabaseManager(self.db_file)
        vulns_dict = defaultdict(list)
        rows = db_manager.get_vulns()
        for row in rows:
            vulns_dict[row[0]]=row
        db_manager.close()
        gc.collect()
        return vulns_dict

    def version_comparison(self, package):
        architecture_suffixes = ['.x86_64', '.aarch64', '.mips64el', '.loongarch64', '.noarch', '_amd64', '_mips64el',
                              '_loongarch64', '_all']
        try:
            for row in self.vulns.values():
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

                if not all([package_suffix, fixed_package_suffix, package_prefix, solution]):
                    continue

                if package_suffix in fixed_package_suffix and package_prefix in solution and self.system_version in solution:
                    for Fixed_package in Fixed_packages:
                        if package_prefix == self.packages_prefix_extract(Fixed_package):
                            if version.parse(package_name) < version.parse(Fixed_package):
                                cve_id, cve_description = self.extract_kve(description)
                                if cve_id is None:
                                    break
                                else:
                                    return package, risk, vul, cve_id, cve_description, solution, self.ip_port
        except Exception as e:
            self.log.error(f"[*]Error in version_comparison: {e}")

    def packages_prefix_extract(self, text):
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

    def packages_address_extract(self, text, architecture_suffixes):
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

    def extract_kve(self, description):
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

    def query_cve(self):
        """
        执行 CVE 查询的辅助函数。

        参数:
        db_file (str): 数据库文件的路径。
        packages (list): 软件包列表。
        kylinos_version (str): 软件包版本。
        ip_port (str): IP 端口信息。
        """
        queries = []
        future_queue = Queue()
        with ThreadPoolExecutor(max_workers=5) as executor:
            for line in self.packages:
                package = line.strip()
                future = executor.submit(self.version_comparison, package)
                future_queue.put(future)
            for future in as_completed(future_queue.queue):
                result = future.result()
                if result:
                    queries.append(result)
        return queries
