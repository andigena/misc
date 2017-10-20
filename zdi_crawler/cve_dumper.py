#!/usr/bin/env python3
""" Builds a simple HTML list of your ZDI submissions by crawling the 'My Cases' section of the ZDI site and matching
entries up with CVE numbers (needs a session id for the site).
"""
import collections
import logging
import re
import requests
import sys

import requests_cache
requests_cache.install_cache('cache')

Vulnerability = collections.namedtuple('Vulnerability', ('zdi_id', 'cve_id', 'title'))

SESSION = sys.argv[1] if len(sys.argv) > 1 else input('Show me your session id: ')
ZDI = 'https://www.zerodayinitiative.com'
MY_CASES = ZDI + '/portal/my_cases/'
ADVISORIES = ZDI + '/advisories/'


def get_zdi_id(case_data):
    m = re.search(r'''This case has been publicly disclosed as (ZDI-\d{2}\-\d{3})''', case_data)
    if not m:
        if tmp.find('This case has been officially contracted to the ZDI.') != -1:
            logging.warning('''{} was contracted but there's no ZDI id (multiple vulns in one report?)'''.format(case))
        return None
    else:
        return m.group(1)


def get_cve_id(case_data):
    m = re.search(r'''(CVE-\d{4}-\d{4,})''', case_data)
    if not m:
        return None
    else:
        return m.group(1)


def get_product_info(advisory_data):
    m = re.search(r'''Affected Products.+?href="(.*?)">(.*?)</a>''', advisory_data, re.DOTALL)
    if not m:
        return None, None
    else:
        return m.group(1), m.group(2)


def get_vendor_info(advisory_data):
    m = re.search(r'''Affected Vendors.+?href="(.*?)">(.*?)</a>''', advisory_data, re.DOTALL)
    if not m:
        return None, None
    else:
        return m.group(1), m.group(2)


def get_title(advisory_data):
    m = re.search(r'''<div id="main-content">\s+<h2>(.*?)</h2>''', advisory_data, re.DOTALL)
    if not m:
        return None, None
    else:
        return m.group(1)


if __name__ == '__main__':
    cases = ''
    cookies = dict(sessionid='')
    r = requests.get(MY_CASES, cookies=cookies)
    cases = r.content.decode('utf8')
    vulnerabilities = {}

    for case in re.findall(r'''a href="/portal/my_cases/(.+?)/">''', cases):
        case_data = tmp = requests.get(MY_CASES + case, cookies=cookies).content.decode('utf8')
        zdi_id = get_zdi_id(case_data)
        if not zdi_id:
            # the submission wasn't acquired/published by ZDI (yet?)
            continue

        advisory_data = requests.get(ADVISORIES + zdi_id, cookies=cookies).content.decode('utf8')
        product_url, product_name = get_product_info(advisory_data)
        vendor_url, vendor_name = get_vendor_info(advisory_data)
        cve_id = get_cve_id(advisory_data)
        title = get_title(advisory_data)

        if product_name not in vulnerabilities:
            vulnerabilities[product_name] = dict(product_url=product_url, vendor_name=vendor_name, vendor_url=vendor_url, vulns=[])
        vulnerabilities[product_name]['vulns'].append(Vulnerability(zdi_id, cve_id, title))

    for product, d in vulnerabilities.items():
        print('<h2>{} {}</h2>'.format(d['vendor_name'], product))
        for v in d['vulns']:
            print('<a href="{}">{} - {}</a><br/>'.format(ADVISORIES + v.zdi_id, v.cve_id, v.title))
        print()
