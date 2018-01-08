#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''

from plugins import core
import re
import os
import sys
import random

class HoppyPlugin(core.PluginBase):
    """
    Example plugin to parse nmap output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Hoppy"
        self.name = "Hoppy"
        self.version = "0.0.1"
        self.framework_version = "1.0.0"
        self.plugin_version = "1.0.0"
        self._command_regex = re.compile(r' *[\/\w\.-]*(sudo hoppy|hoppy|\.\/hoppy).*?')

    def parseOutputString(self, output, debug=False):
        """ function doc
        """

        m = re.search(r"\[\+\] Test host.*resolves to ([\d\.]+)", output)
        host_ip = m.group(1)
        h_id = self.createAndAddHost(host_ip)
        i_id = self.createAndAddInterface(h_id,host_ip)
        m = re.search(r"\[\+\] Testing Connection to ([\w\d\.:]+) ", output)
        host_port = m.group(1).split(':')

        host = host_port[0]
        port = 80
        if len(host_port)>1:
            port = host_port[1]

        s_id = self.createAndAddServiceToInterface(
            h_id,
            i_id,
            'http',
            'tcp',
            ports=[port])

        current_section = None
        for line in output.splitlines():
            if "[+] Information Leakage:" in line:
                current_section = "leakinfo"
                continue
            if "[+] IP Leakage:" in line:
                current_section = "ipleakage"
                continue
            if "[+] Extracted Data:" in line:
                current_section = "exdata"
                continue
            elif "[+]" in line:
                current_section = None
                continue
            
            clean_line = line.strip()
            if clean_line  == '':
                continue
            
            if current_section == "leakinfo":
                self.createAndAddNoteToService(h_id, s_id, "Information Leakage", clean_line)
            elif current_section == "ipleakage":
                self.createAndAddNoteToService(h_id, s_id, "IP Leakage", clean_line)
            elif current_section == "exdata":
                self.createAndAddNoteToService(h_id, s_id, "Extracted Data", clean_line)
            
        return True

    def processCommandString(self, username, current_path, command_string):
        pass


def createPlugin():
    return HoppyPlugin()

if __name__ == '__main__':
    pass
