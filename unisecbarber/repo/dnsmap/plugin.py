#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)

'''

from __future__ import with_statement
from plugins import core
import re
import os
import sys
import random

current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class DnsmapParser(object):
    """
    The objective of this class is to parse an xml file generated by the
    dnsmap tool.

    TODO: Handle errors.
    TODO: Test dnsmap output version. Handle what happens if the parser
    doesn't support it.
    TODO: Test cases.

    @param dnsmap_filepath A proper simple report generated by dnsmap
    """

    def __init__(self, output):

        self.items = []
        lists = output.split("\n")

        for line in lists:
            mitem = line.split(',')
            if len(mitem) > 1:
                item = {'host': mitem[0], 'ip': mitem[1]}
                self.items.append(item)


class DnsmapPlugin(core.PluginBase):
    """Example plugin to parse dnsmap output."""

    def __init__(self):

        core.PluginBase.__init__(self)
        self.id = "Dnsmap"
        self.name = "Dnsmap XML Output Plugin"
        self.plugin_version = "0.0.2"
        self.version = "0.30"
        self.options = None
        self._current_output = None
        self.current_path = None
        self._command_regex = re.compile(
            r'^(sudo dnsmap|dnsmap|\.\/dnsmap).*?')

        self.xml_arg_re = re.compile(r"^.*(-c\s*[^\s]+).*$")

        global current_path

        self._output_file_path = os.path.join(
            self.data_path,
            "%s_%s_output-%s.xml" % (
                self.get_ws(),
                self.id,
                random.uniform(1, 10)
            )
        )

    def canParseCommandString(self, current_input):
        if self._command_regex.match(current_input.strip()):
            return True
        else:
            return False

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.
        """

        parser = DnsmapParser(output)

        for item in parser.items:
            h_id = self.createAndAddHost(item['ip'])
            self.createAndAddInterface(
                h_id,
                item['ip'],
                ipv4_address=item['ip'],
                hostname_resolution=item['host'])

        return True

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the parameter to get output to the command string that the
        user has set.
        """
        arg_match = self.xml_arg_re.match(command_string)

        if arg_match is None:
            return "%s -c %s \n" % (command_string, self._output_file_path)
        else:
            return re.sub(arg_match.group(1),
                          r"-c %s" % self._output_file_path,
                          command_string)


def createPlugin():
    return DnsmapPlugin()

if __name__ == '__main__':
    parser = DnsmapParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print item
