#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ted 0.0.1
#
# Copyright © Jon Hood, http://www.hoodsecurity.com/
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import datetime
import gzip
import json
import os.path
import sys
import time
import requests
import urllib3
import xml.etree.ElementTree as ET
from base64 import b64encode
from packaging import version
from pathlib import Path

def main():
    nuget_url = "https://azuresearch-usnc.nuget.org/query?q=packageid:{}"
    nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz"
    ossindex_url = "https://ossindex.sonatype.org/api/v3/component-report/pkg:nuget/{}@{}"
    
    ossindexKey = ""
    ossindexUser = ""
    
    parser = argparse.ArgumentParser(usage='%(prog)s [-r -o -h -v --no-ssl] path', description='Ted. NuGet package vulnerability checker.')

    parser.version = "0.1"
    parser.add_argument("Path", metavar="path", type=str, help="the path to the packages.config file, or the directory to search if the -r flag is used.")
    parser.add_argument("-o", "--output", required=True, type=str, help="Output file location.")
    parser.add_argument("--no-ssl", action="store_true", dest="no_ssl_verify", help="Verify SSL. Turn off ssl verification. Useful if there are certification issues.")
    parser.add_argument("-r", "-R", "--recursive", action="store_true", dest="recursive", help="Recursively searches directory for all packages.config files.")
    parser.add_argument("-v", action="version")

    args = parser.parse_args()
    input = args.Path
    output = args.output
    recursive = args.recursive
    no_ssl_verify = args.no_ssl_verify
    
    req_session = requests.Session()
    
    if no_ssl_verify:
        req_session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    #set up the config files to scan
    configs = []
    
    if not os.path.exists(input):
        print("The supplied path does not exist: {}".format(input))
    else:
        if recursive:
            print("Recursively searching {} for all packages.config files:".format(input))
            for filename in Path(input).rglob('packages.config'):
                print("\t{}".format(filename))
                configs.append(filename)
        else:
            configs.append(input)

    #build a dictionary of CVEs
    cves = {}
    now = datetime.datetime.now()
    #index the NVD
    if os.path.exists(str(now.year) + ".json"):
        #check if latest NVD file is more than 7 days old
        if time.time() - os.path.getmtime(str(now.year) + ".json") > 7 * 24 * 60 * 60:
            os.remove(str(now.year) + ".json")
    #download the NVD record for each year through the current one
    for y in range(2002, now.year + 1):
        y = str(y)
        if os.path.exists(y + ".json"):
            #if the json file is stale, update it.
            if time.time() - os.path.getmtime(y + ".json") > 30 * 24 * 60 * 60:
                os.remove(y + ".json")
        if not os.path.exists(y + ".json"):
            print("Downloading NVD for " + y)
            response = req_session.get(nvd_url.format(y))
            print(response.status_code)
            print(response.headers['content-type'])
            print(response.encoding)
            f = open(y + ".json", "wb")
            f.write(gzip.decompress(response.content))
            f.close()
        if os.path.exists(y + ".json"):
            print("Loading CVE data for {}".format(y))
            try:
                with open(y + ".json") as jsonFile:
                    data = json.load(jsonFile)
                    for cve in data['CVE_Items']:
                        cveId = cve['cve']['CVE_data_meta']['ID']
                        for node in cve['configurations']['nodes']:
                            if 'cpe_match' in node:
                                for products in node['cpe_match']:
                                    cpe = products['cpe23Uri'].split(':')
                                    if cveId not in cves:
                                        cves[cveId] = {}
                                    if cpe[4] not in cves[cveId]:
                                        cves[cveId][cpe[4]] = []
                                    affected = "*"
                                    if 'versionEndIncluding' in cpe:
                                        cpe[5] = cpe['versionEndIncluding']
                                        affected = "<="
                                    cves[cveId][cpe[4]].append(affected + cpe[5])
            except Exception as e:
                print("\tERROR loading CVE data for {}".format(y))
                print("\t{}".format(e))
       
    packages = {}
    
    #loop through each packages.config file provided
    for config in configs:
        tree = ET.parse(config)
        root = tree.getroot()
        for package in root.findall('./package'):
            key = package.attrib['id'] + "@" + package.attrib['version']
            if key in packages:
                packages[key].append(str(config))
            else:
                packages[key] = [str(config)]
    
    print("Checking packages for vulnerabilities")
    with open(output, 'w') as out_file:
        out_file.write("CWE/CVE/STIG,Confidence,Exploit Maturity,Mitigations,Comments,Tool,File\n")
     
        for package in packages:
            print("Checking {}".format(package))
            package_id = package.split('@')[0]
            package_version = package.split('@')[1]
            loc = "|".join(packages[package])
            response = req_session.get(nuget_url.format(package_id))
            data = response.json()
            time.sleep(1)

            if 'data' not in data:
                print("\tERROR contacting nuget.")
                continue
            if len(data['data']) < 1:
                continue
            print("\tCurrent version is {}. Checking OSS Index...".format(data['data'][0]['version']))
            if package_version != data['data'][0]['version']:
                out_file.write("SV-85017r2_rule,Confirmed,Proof of Concept,None,The latest version of {} is {} but {} is installed.,Ted,{}\n".format( 
                package_id,
                data['data'][0]['version'],
                package_version,
                loc))

            #check OSS Index
            formatted_ossindex_url = ossindex_url.format(package_id, package_version)
            if (len(ossindexKey) > 0) and (len(ossindexUser) > 0):
                response = req_session.get(formatted_ossindex_url, auth=(ossindexUser, ossindexKey))
            else:
                response = req_session.get(formatted_ossindex_url)
            data = response.json()
            printedCves = []
            for vuln in data['vulnerabilities']:
                if 'cve' in vuln:
                    #CVE found
                    col1 = vuln['cve']
                    printedCves.append(vuln['cve'])
                elif 'cwe' in vuln:
                    col1 = vuln['cwe']
                else:
                    col1 = ''
                
                out_file.write("{},Confirmed,High,None,{} ({}),Ted,{},\n".format(
                col1,
                vuln['title'].replace(',', ''),
                vuln['reference'],
                loc))
                print("\tVunerability found: {} {} {}".format(col1, vuln['title'].replace(',', ''), vuln['reference'], loc))

            #print out each CVE that was found against the product
            markedCves = []
            for cve in cves:
                for product in cves[cve]:
                    if product == package_id.lower():
                        versions = cves[cve][product]
                        for versionStr in versions:
                            versionToTest = versionStr[1:]
                            versionComparison = versionStr[0]
                            if versionToTest.startswith("="):
                                versionComparison = versionComparison + "="
                                versionToTest = versionToTest[1:]
                            if versionComparison == "<":
                                if (version.parse(package_version) < version.parse(versionToTest)):
                                    markedCves.append(cve)
                                    break
                            if versionComparison == "<=":
                                if (version.parse(package_version) <= version.parse(versionToTest)):
                                    markedCves.append(cve)
                                    break
                            elif (versionComparison == "="):
                                if (version.parse(package_version) == version.parse(versionToTest)):
                                    markedCves.append(cve)
                                    break
            for markedCve in markedCves:
                if markedCve in printedCves:
                    continue
                printedCves.append(markedCve)
                out_file.write("{},Confirmed,High,None,{} contains known vulnerability information against {} {}.,Ted,{}\n".format(
                markedCve,
                markedCve,
                package_id,
                package_version,
                loc))
    
    print("Finished writing vulnerabilities to {}".format(output))

if __name__== "__main__":
    main()
