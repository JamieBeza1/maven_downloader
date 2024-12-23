import json
import pycurl
import requests
import os
from io import BytesIO
import csv


def setup_working_directory():
    dir = os.getcwd()
    target_dir = 'pkg'
    try:
        os.mkdir(os.path.join(dir, target_dir))
        print(f"Directory Created: {target_dir}")
    except:
        print(f"Directory '{target_dir}' already exists")
    finally:
        working_dir = dir + "/" + target_dir

    return working_dir

def check_if_is_file(filename):
    default_file = 'package.txt'
    if filename is None:
        if os.path.isfile(default_file):
            print(f"Running recursive download from default file: {default_file}")
            run_from_file(default_file)
        else:
            print(f"Unable to find default file: {default_file}")
    elif filename.endswith(".txt") and os.path.isfile(filename):
        print(f"Running recursive download from specified file: {filename}")
        run_from_file(filename)
    else:
        print(f"Unable to locate file: {filename}")

def run_from_file(filename):
    with open(filename) as file:
        for line in file:
            print(line)

def get_pkg_details():
    base = 'https://api.deps.dev/v3alpha/systems/maven/packages/'
    maven_base = "https://repo1.maven.org/maven2"
    versions = '/versions/'
    dependencies_str = ':dependencies'
    package_name = input("Please enter the Maven package you want to download or enter the location of a file containing all the packages (Defualt packages.txt) : ")
    package_version = input("Please enter the Package version here: ")
    #pkg_name = base + package_name + versions + package_version
    return package_name, package_version, base + package_name + versions + package_version, {}, {}, setup_working_directory(), base, maven_base

class Package:

    def __init__(self, name, version, url, dependencies, advisories, working_dir, base, maven_base):
        self.name = name
        self.version = version
        self.pkg_url = url
        self.dependencies = dependencies
        self.advisories = advisories
        self.working_dir = working_dir
        self.url_base = base
        self.maven_base = maven_base

    def call_api(self, command):
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, command)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()

        body = buffer.getvalue()
        return body.decode('utf-8')

    def populate_dependencies(self):
        try:
            json_data = self.call_api(self.pkg_url+':dependencies')
            data = json.loads(json_data)

            try:
                for node in data['nodes']:
                    dep_name = node['versionKey']['name']
                    dep_version = node['versionKey']['version']
                    self.dependencies[dep_name] = {'version': dep_version, 'advisories': self.populate_advisories(dep_name, dep_version)}
            except:
                print(f"Error checking dependency {dep_name}")


        except:
            print(f"Error calling API for package {self.name}")

        for node in data['nodes']:
            dep_name = node['versionKey']['name']
            dep_version = node['versionKey']['version']
            self.dependencies[dep_name] = {'version': dep_version, 'advisories': self.populate_advisories(dep_name, dep_version)}

        self.create_advisories_list(self.dependencies)


    def populate_advisories(self, dep, version):
        advisories = []

        json_data = self.call_api(self.url_base + dep + '/versions/' + version)
        data = json.loads(json_data)

        advisories.append(data['advisoryKeys'])

        return advisories

    def print_object(self):
        print(f"Package Name: {self.name}\nVerison: {self.version}\nDependencies: {self.dependencies}\nSecurity Advisories ({len(self.advisories)} found): {self.advisories}\nBase URL: {self.pkg_url}")


    def create_advisories_list(self, dependency):
        for dep_name, dep_info in dependency.items():
            if dep_info['advisories']:
                for advisory_list in dep_info['advisories']:
                    if advisory_list:
                        for advisory in advisory_list:
                            if isinstance(advisory, dict) and 'id' in advisory:
                                #print(f"  - Advisory ID: {advisory['id']}")
                                self.advisories[f"{dep_name}:{advisory['id']}"] = advisory['id']
                                #self.advisories[dep_name].append(advisory['id'])
                    else:
                        pass
            else:
                pass
            pass

    def build_urls(self, pkg_name, version, ext):
        base_url = "https://repo1.maven.org/maven2"
        sliced = pkg_name.split(':', 1)
        new_path = sliced[0].replace(".", "/")
        artifact = sliced[-1]
        full_url = f"{base_url}/{new_path}/{artifact}/{version}/{artifact}-{version}{ext}"
        return full_url

    def download_package(self, package_name, version, filename, ext):
        url = self.build_urls(package_name, version, ext)
        response = requests.get(url)
        short_fname = filename.split(":", 1)
        if response.status_code == 200:
            with open(os.path.join(self.organise_directory(filename, version), f"{short_fname[-1]}-{version}{ext}"),
                      "wb") as file:
                file.write(response.content)
            print(f"Downloaded {filename}@v{version} successfully")
        else:
            print(f"Failed to download {filename} - HTTP error code: {response.status_code}")

    def download_jars_poms(self):
        for dep_name, dep_info in self.dependencies.items():
            self.download_package(dep_name, dep_info['version'], dep_name, ".pom")
            self.download_package(dep_name, dep_info['version'], dep_name, ".jar")
            self.download_package(dep_name, dep_info['version'], dep_name, ".aar")
            self.download_package(dep_name, dep_info['version'], dep_name, ".module")

    def organise_directory(self, filename, version):
        sep = filename.split(":", 1)
        dirs = sep[0].replace(".", "/")
        fin_dirs = (dirs + f"/{sep[-1]}/{version}").split("/")
        full_dir = os.path.join(self.working_dir, *fin_dirs)

        if not os.path.exists(full_dir):
            os.makedirs(full_dir)
            print(f"Directory Created: {full_dir}")
        return full_dir

    def pull_cves(self, ad_key):
        url = 'https://api.deps.dev/v3alpha/advisories/' + ad_key
        json_data = self.call_api(url)
        data = json.loads(json_data)

        return data

    def get_cve_details(self):
        data = []
        for vuln in self.advisories:
            print(vuln)
            name = vuln.split(":")
            jsons = self.pull_cves(name[-1])
            #print(f"JSONS: {jsons}")
            cve_num = None

            for alias in jsons['aliases']:
                if alias.startswith('CVE-'):
                    cve_num = alias
                    break



            if not cve_num:
                cve_num = 'No CVE found'

            cve_details = {
                'CVE Number': cve_num,
                'Package Name': name[0],
                'Version': name[-1],
                'Title': jsons['title'],
                'CVSS Score': jsons['cvss3Score'],
                'CVSS Vector': jsons['cvss3Vector']
            }
            data.append(cve_details)

        return data

    def write_report(self):
        with open('vulnerability_report.csv', 'w', newline='') as csvfile:
            fieldnames = ['CVE Number', 'Package Name', 'Version', 'Title', 'CVSS Score', 'CVSS Vector']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.get_cve_details())
            print("Vulnerability Report Created @vulnerability_report.csv")

    def main(self):
        maven.populate_dependencies()
        maven.print_object()
        maven.download_jars_poms()
        maven.get_cve_details()
        maven.write_report()


if __name__ == '__main__':
    pkg_details = get_pkg_details()
    maven = Package(*pkg_details)
    maven.main()