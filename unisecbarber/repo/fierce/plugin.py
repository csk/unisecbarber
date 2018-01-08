#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)

'''
from __future__ import with_statement
from plugins import core
import socket
import re
import os
import sys

current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"

valid_records = ["NS", "CNAME", "A"]


class FierceParser(object):
    """
    The objective of this class is to parse an shell output generated by
    the fierce tool.

    TODO: Handle errors.
    TODO: Test fierce output version. Handle what happens if the parser
    doesn't support it.
    TODO: Test cases.

    @param fierce_filepath A proper simple report generated by fierce
    """

    def __init__(self, output):

        self.target = None
        self.items = []

        r = re.search(
            "DNS Servers for ([\w\.-]+):\r\n([^$]+)Trying zone transfer first...",
            output)

        if r is not None:
            self.target = r.group(1)
            mstr = re.sub("\t", "", r.group(2))
            self.dns = mstr.split()

        r = re.search(
            "Now performing [\d]+ test\(s\)...\r\n([^$]+)\x0D\nSubnets found ",
            output)

        if r is not None:
            list = r.group(1).split("\r\n")
            for i in list:
                if i != "":
                    mstr = i.split("\t")
                    item = {'host': mstr[1], 'type': "A", 'ip': mstr[0]}
                    self.items.append(item)

        self.isZoneVuln = False
        output= output.replace('\\$', '')
        r = re.search(
            "Whoah, it worked - misconfigured DNS server found:([^$]+)\There isn't much point continuing, you have  everything.", output)

        if r is not None:

            self.isZoneVuln = True
            list = r.group(1).split("\n")
            for i in list:

                if i != "":
                    mstr = i.split()
                    if (mstr and mstr[0] != "" and len(mstr) > 3 and mstr[3] in valid_records):
                        item = {'host': mstr[0],
                                'type': mstr[3], 'ip': mstr[4]}
                        self.items.append(item)


class FiercePlugin(core.PluginBase):
    """
    Example plugin to parse fierce output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Fierce"
        self.name = "Fierce Output Plugin"
        self.plugin_version = "0.0.1"
        self.version = "0.9.9"
        self.options = None
        self._current_output = None
        self._current_path = None
        self._command_regex = re.compile(
            r'^(sudo fierce|fierce|sudo fierce\.pl|fierce\.pl|perl fierce\.pl|\.\/fierce\.pl).*?')
        global current_path

    def canParseCommandString(self, current_input):
        if self._command_regex.match(current_input.strip()):
            return True
        else:
            return False

    def resolveCNAME(self, item, items):
        for i in items:
            if (i['host'] == item['ip']):
                item['ip'] = i['ip']
                return item
        try:
            item['ip'] = socket.gethostbyname(item['ip'])
        except:
            pass
        return item

    def resolveNS(self, item, items):
        try:
            item['host'] = item['ip']
            item['ip'] = socket.gethostbyname(item['ip'])
        except:
            pass
        return item

    def parseOutputString(self, output, debug=False):

        parser = FierceParser(output)
        for item in parser.items:

            item['isResolver'] = False
            item['isZoneVuln'] = False
            if (item['type'] == "CNAME"):
                self.resolveCNAME(item, parser.items)
            if (item['type'] == "NS"):
                self.resolveNS(item, parser.items)
                item['isResolver'] = True
                item['isZoneVuln'] = parser.isZoneVuln
                for item2 in parser.items:

                    if item['ip'] == item2['ip'] and item != item2:
                        item2['isResolver'] = item['isResolver']
                        item2['isZoneVuln'] = item['isZoneVuln']
                        item['ip'] = ''

        for item in parser.items:

            if item['ip'] == "127.0.0.1" or item['ip'] == '':
                continue
            h_id = self.createAndAddHost(item['ip'])
            i_id = self.createAndAddInterface(
                h_id,
                item['ip'],
                ipv4_address=item['ip'],
                hostname_resolution=[item['host']])

            if item['isResolver']:
                s_id = self.createAndAddServiceToInterface(
                    h_id,
                    i_id,
                    "domain",
                    "tcp",
                    ports=['53'])

                if item['isZoneVuln']:
                    self.createAndAddVulnToService(
                        h_id,
                        s_id,
                        "Zone transfer",
                        desc="A Dns server allows unrestricted zone transfers",
                        ref=["CVE-1999-0532"])

    def processCommandString(self, username, current_path, command_string):
        return None


def createPlugin():
    return FiercePlugin()

if __name__ == '__main__':
    parser = FierceParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print item
