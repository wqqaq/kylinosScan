import gc
import re

from packaging import version
from lib.model.database import DatabaseManager

class Utils:
    @staticmethod
    def version_comparison(db_file, package, system_version,ip_port):
        architecture_suffixes = ['.x86_64', '.aarch64', '.mips64el', '.loongarch64', '.noarch', '_amd64', '_mips64el',
                                 '_loongarch64', '_all']
        db_manager = DatabaseManager(db_file)
        rows = db_manager.get_vulns()
        try:
            for row in rows:
                risk = row[2]
                vul = row[3]
                description = row[6]
                fixed_package_suffix = str(row[8])
                solution = str(row[10])
                package_suffix = ''
                package_name = ''
                Fixed_packages = Utils.packages_address_extract(solution, architecture_suffixes)
                for suffix in architecture_suffixes:
                    if package.endswith(suffix):
                        package_name = package.replace(suffix, '').split()[0]  # 当前包 libfastjson-0.99.9-3.ky10
                        package_suffix = suffix.replace('.', '')
                package_prefix = Utils.packages_prefix_extract(package)

                if not all([package_suffix,fixed_package_suffix,package_prefix,solution]):
                    continue

                if package_suffix in fixed_package_suffix and package_prefix in solution and system_version in solution:
                    for Fixed_package in Fixed_packages:
                        if package_prefix == Utils.packages_prefix_extract(Fixed_package):
                            if version.parse(package_name) < version.parse(Fixed_package):
                                # while True:
                                    cve_id, cve_description = Utils.extract_kve(description)
                                    if cve_id is None:
                                        break
                                    else:
                                        return package, risk, vul, cve_id, cve_description, solution, ip_port
        finally:
            db_manager.close()
            gc.collect()
        return False

    @staticmethod
    def extract_kve(description):
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
            print(f"extract_kve error: {e}")
            return None, None
        return cve_id, cve_description

    @staticmethod
    def packages_prefix_extract(text):
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

    @staticmethod
    def packages_address_extract(text, architecture_suffixes):
        urls = text.split('\n')
        package_names = []
        for url in urls:
            for suffix in architecture_suffixes:
                if suffix in url:
                    last_slash_index = url.rfind('/')
                    suffix_index = url.rfind(suffix)
                    if last_slash_index != -1 and suffix_index != -1 and last_slash_index < suffix_index:
                        package_name = url[last_slash_index + 1:suffix_index]
                        package_names.append(package_name)
        return package_names
