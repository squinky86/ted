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

import datetime
import gzip
import json
import os.path
import ssl
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from base64 import b64encode
from packaging import version

def main(argv):
    #set up the config files to scan
    configs = []
    ossindexKey = ""
    ossindexUser = ""
    if len(argv) <= 1:
        print("Usage:")
        print(argv[0] + " [path(s) to packages.config] 2> output.csv")
        return
    for x in argv[1:]:
        if (os.path.exists(x)):
            configs.append(x)
        else:
            print("File '" + x + "' does not exist.")

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
            response = urllib.request.urlopen("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-" + y + ".json.gz")
            f = open(y + ".json", "wb")
            f.write(gzip.decompress(response.read()))
            f.close()
        if os.path.exists(y + ".json"):
            with open(y + ".json") as jsonFile:
                data = json.load(jsonFile)
                for cve in data['CVE_Items']:
                    cveId = cve['cve']['CVE_data_meta']['ID']
                    for products in cve['cve']['affects']['vendor']['vendor_data']:
                        for product in products['product']['product_data']:
                            for versionStr in product['version']['version_data']:
                                if cveId not in cves:
                                    cves[cveId] = {}
                                if product['product_name'] not in cves[cveId]:
                                    cves[cveId][product['product_name']] = []
                                cves[cveId][product['product_name']].append(versionStr['version_affected'] + versionStr['version_value'])

    sys.stderr.write("CWE/CVE/STIG,Confidence,Exploit Maturity,Mitigations,Comments,Tool,File\n")

    #loop through each packages.config file provided
    for y in configs:
        tree = ET.parse(y)
        root = tree.getroot()
        for package in root.findall('./package'):
            print("Found " + package.attrib['id'] + "-" + package.attrib['version'])
            response = urllib.request.urlopen("https://azuresearch-usnc.nuget.org/query?q=packageid:" + package.attrib['id'])
            data = json.loads(response.read())
            time.sleep(1)

            if 'data' not in data:
                print("\tError contacting nuget.")
                continue
            if len(data['data']) < 1:
                print("\tNot found in nuget.")
                continue
            print("\tCurrent version is " + data['data'][0]['version'])
            if package.attrib['version'] != data['data'][0]['version']:
                sys.stderr.write("SV-85017r2_rule,Confirmed,Proof of Concept,None,The latest version of " + package.attrib['id'] + " is " + data['data'][0]['version'] + " but " + package.attrib['version'] + " is installed.,Ted," + y + "\n")

            #check OSS Index
            req = urllib.request.Request("https://ossindex.sonatype.org/api/v3/component-report/pkg:nuget/" + package.attrib['id'] + "@" + package.attrib['version'])
            if (len(ossindexKey) > 0) and (len(ossindexUser) > 0):
                basicAuth = b64encode((ossindexUser + ":" + ossindexKey).encode()).decode("ascii")
                req.add_header("authorization", "Basic " + basicAuth)
            response = urllib.request.urlopen(req, context=ssl._create_unverified_context())
            data = json.loads(response.read())
            printedCves = []
            for vuln in data['vulnerabilities']:
                if 'cve' in vuln:
                    #CVE found
                    sys.stderr.write(vuln['cve'] + ",Confirmed,High,None," + vuln['title'].replace(',', '') + " (" + vuln['reference'] + "),Ted," + y + "\n")
                    printedCves.append(vuln['cve'])
                else:
                    sys.stderr.write(vuln['cwe'] + ",Confirmed,High,None," + vuln['title'].replace(',', '') + " (" + vuln['reference'] + "),Ted," + y + "\n")

            #print out each CVE that was found against the product
            markedCves = []
            for cve in cves:
                for product in cves[cve]:
                    if product == package.attrib['id'].lower():
                        versions = cves[cve][product]
                        for versionStr in versions:
                            versionToTest = versionStr[1:]
                            versionComparison = versionStr[0]
                            if versionToTest.startswith("="):
                                versionComparison = versionComparison + "="
                                versionToTest = versionToTest[1:]
                            if versionComparison == "<":
                                if (version.parse(package.attrib['version']) < version.parse(versionToTest)):
                                    markedCves.append(cve)
                                    break
                            if versionComparison == "<=":
                                if (version.parse(package.attrib['version']) <= version.parse(versionToTest)):
                                    markedCves.append(cve)
                                    break
                            elif (versionComparison == "="):
                                if (version.parse(package.attrib['version']) == version.parse(versionToTest)):
                                    markedCves.append(cve)
                                    break
            for markedCve in markedCves:
                if markedCve in printedCves:
                    continue
                printedCves.append(markedCve)
                sys.stderr.write(markedCve + ",Confirmed,High,None," + markedCve + " contains known vulnerability information against " + package.attrib['id'] + " " + package.attrib['version'] + ".,Ted," + y + "\n")


if __name__== "__main__":
    main(sys.argv)
