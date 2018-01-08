#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)

'''
from plugins import core
import re


class OwtfPtes003BruteforcePlugin(core.PluginBase):
    """
    Example plugin to parse nmap output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "OwtfPtes003Bruteforce"
        self.name = "OWTF PTES 003 Bruteforce"
        self.plugin_version = "0.0.1"
        # self.version = "6.40"
        # self.framework_version = "1.0.0"
        # self.options = None
        # self._current_output = None
        self._command_regex = re.compile(r'.*msfconsole.*use auxiliary\/scanner\/vnc\/vnc_login')


    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        login_success_re = r'([\w.]+):(\d+).*Login Successful: (.*):(.+)'
        for line in output.splitlines():
            m = re.search(login_success_re,line)
            if m is None:
                continue

            ipv4 = m.group(1)
            port = m.group(2)
            username = m.group(3)
            password = m.group(4)

            
            minterfase = ipv4
            h_id = self.createAndAddHost(ipv4)
            i_id = self.createAndAddInterface(
                h_id,
                minterfase,
                ipv4_address=ipv4)
            
            s_id = self.createAndAddServiceToInterface(
                    h_id,
                    i_id,
                    'vnc',
                    'tcp',
                    ports=[port]
                    )
            self.createAndAddCredToService(
                    h_id,
                    s_id,
                    username,
                    password)

        return True

    def processCommandString(self, username, current_path, command_string):
       
       return


def createPlugin():
    return OwtfPtes003BruteforcePlugin()
