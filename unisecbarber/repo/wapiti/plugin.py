#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)

'''
from __future__ import with_statement
from plugins import core
from model import api
import re
import os
import pprint
import sys

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class WapitiXmlParser(object):
    """
    The objective of this class is to parse an xml file generated by the wapiti tool.

    TODO: Handle errors.
    TODO: Test wapiti output version. Handle what happens if the parser doesn't support it.
    TODO: Test cases.

    @param wapiti_xml_filepath A proper xml generated by wapiti
    """

    def __init__(self, xml_output):

        tree = self.parse_xml(xml_output)

        if tree:
            self.items = [data for data in self.get_items(tree)]
        else:
            self.items = []

    def parse_xml(self, xml_output):
        """
        Open and parse an xml file.

        TODO: Write custom parser to just read the nodes that we need instead of
        reading the whole file.

        @return xml_tree An xml tree instance. None if error.
        """
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError, err:
            print "SyntaxError: %s. %s" % (err, xml_output)
            return None

        return tree

    def get_items(self, tree):
        """
        @return items A list of Host instances
        """
        bugtype = ""

        bug_typelist = tree.findall('bugTypeList')[0]
        for bug_type in bug_typelist.findall('bugType'):

            bugtype = bug_type.get('name')

            bug_list = bug_type.findall('bugList')[0]
            for item_bug in bug_list.findall('bug'):
                yield Item(item_bug, bugtype)


"""
<bugTypeList>
<bugType name="File Handling"><bugList><bug level="1"><url>
                        http://www.saludactiva.org.ar/index.php?id=http%3A%2F%2Fwww.google.fr%2F
                    </url><parameter>
                        id=http%3A%2F%2Fwww.google.fr%2F
                    </parameter><info>
                        Warning include() (id)
                    </info>
"""


def get_attrib_from_subnode(xml_node, subnode_xpath_expr, attrib_name):
    """
    Finds a subnode in the item node and the retrieves a value from it

    @return An attribute value
    """
    global ETREE_VERSION
    node = None

    if ETREE_VERSION[0] <= 1 and ETREE_VERSION[1] < 3:

        match_obj = re.search(
            "([^\@]+?)\[\@([^=]*?)=\'([^\']*?)\'", subnode_xpath_expr)
        if match_obj is not None:
            node_to_find = match_obj.group(1)
            xpath_attrib = match_obj.group(2)
            xpath_value = match_obj.group(3)
            for node_found in xml_node.findall(node_to_find):
                if node_found.attrib[xpath_attrib] == xpath_value:
                    node = node_found
                    break
        else:
            node = xml_node.find(subnode_xpath_expr)

    else:
        node = xml_node.find(subnode_xpath_expr)

    if node is not None:
        return node.get(attrib_name)

    return None


class Item(object):
    """
    An abstract representation of a Item

    TODO: Consider evaluating the attributes lazily
    TODO: Write what's expected to be present in the nodes
    TODO: Refactor both Host and the Port clases?

    @param item_node A item_node taken from an wapiti xml tree
    """

    def __init__(self, item_node, bugtype):
        self.node = item_node

        self.bugtype = bugtype
        self.buglevel = self.node.get('level')
        self.url = self.do_clean(self.get_text_from_subnode('url'))
        self.parameter = self.do_clean(self.get_text_from_subnode('parameter'))
        self.info = self.do_clean(self.get_text_from_subnode('info'))

    def do_clean(self, value):
        myreturn = ""
        if value is not None:
            myreturn = re.sub("\n", "", value)
        return myreturn

    def get_text_from_subnode(self, subnode_xpath_expr):
        """
        Finds a subnode in the host node and the retrieves a value from it.

        @return An attribute value
        """
        sub_node = self.node.find(subnode_xpath_expr)
        if sub_node is not None:
            return sub_node.text

        return None


class WapitiPlugin(core.PluginBase):
    """
    Example plugin to parse wapiti output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Wapiti"
        self.name = "Wapiti XML Output Plugin"
        self.plugin_version = "0.0.1"
        self.version = "2.2.1"
        self.options = None
        self._current_output = None
        self.protocol = None
        self.host = None
        self.port = "80"
        self._command_regex = re.compile(
            r'^(python wapiti|wapiti|sudo wapiti|sudo wapiti\.py|wapiti\.py|python wapiti\.py|\.\/wapiti\.py|wapiti|\.\/wapiti|python wapiti|python \.\/wapiti).*?')
        self._completition = {
            "": "python wapiti.py http://server.com/base/url/ [options]",
            "-s": "&lt;url&gt; ",
            "--start": "&lt;url&gt; ",
            "-x": "&lt;url&gt; ",
            "--exclude": "&lt;url&gt; ",
            "-p": "&lt;url_proxy&gt; ",
            "--proxy": "&lt;url_proxy&gt; ",
            "-c": " -c &lt;cookie_file&gt; ",
            "--cookie": "&lt;cookie_file&gt; ",
            "-t": "&lt;timeout&gt; ",
            "--timeout": "&lt;timeout&gt; ",
            "-a": "&lt;login%password&gt; ",
            "--auth": "&lt;login%password&gt; ",
            "-r": "&lt;parameter_name&gt; ",
            "--remove": "&lt;parameter_name&gt; ",
            "-n": "&lt;limit&gt; ",
            "--nice": "&lt;limit&gt; ",
            "-m": "&lt;module_options&gt; Set the modules and HTTP methods to use for attacks. Example: -m \"-all,xss:get,exec:post\"",
            "--module": "&lt;module_options&gt; Set the modules and HTTP methods to use for attacks. Example: -m \"-all,xss:get,exec:post\"",
            "-u": "Use color to highlight vulnerables parameters in output",
            "--underline": "Use color to highlight vulnerables parameters in output",
            "-v": "&lt;level&gt; ",
            "--verbose": "&lt;level&gt; ",
            "-b": "&lt;scope&gt;",
            "--scope": "&lt;scope&gt;",
            "-f": "&lt;type_file&gt; ",
            "--reportType": "&lt;type_file&gt; ",
            "-o": "&lt;output_file&gt; ",
            "--output": "&lt;output_file&gt; ",
            "-i": "&lt;file&gt;",
            "--continue": "&lt;file&gt;",
            "-k": "&lt;file&gt;",
            "--attack": "&lt;file&gt;",
            "-h": "To print this usage message",
            "--help": "To print this usage message",
        }

        global current_path
        self._output_file_path = os.path.join(self.data_path,
                                              "wapiti_output-%s.xml" % self._rid)

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        self._output_file_path = "/root/dev/faraday/trunk/src/report/wapiti2.3.0_abaco.xml"
        if debug:
            parser = WapitiXmlParser(output)
        else:
            if not os.path.exists(self._output_file_path):
                return False

            parser = WapitiXmlParser(self._output_file_path)

        """
                self.bugtype=bugtype
        self.buglevel=self.node.get('level')
        self.url = self.get_text_from_subnode('url')
        self.parameter = self.get_text_from_subnode('parameter')
        self.info = self.get_text_from_subnode('info')
        """

        h_id = self.createAndAddHost(self.host)
        i_id = self.createAndAddInterface(
            h_id, self.host, ipv4_address=self.host)
        i = 1
        for item in parser.items:
            mport = "%s%i" % (self.port, i)
            s_id = self.createAndAddServiceToInterface(h_id, i_id, mport,
                                                       "tcp",
                                                       [mport],
                                                       status="(%s) (%s)" % (
                                                           item.bugtype, item.url),
                                                       version=item.parameter,
                                                       description=item.info)
            i = i + 1

        del parser

    xml_arg_re = re.compile(r"^.*(-oX\s*[^\s]+).*$")

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the -oX parameter to get xml output to the command string that the
        user has set.
        """
        host = re.search(
            "(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+)).*?$", command_string)

        self.protocol = host.group(1)
        self.host = host.group(4)
        if host.group(11) is not None:
            self.port = host.group(11)
        if self.protocol == 'https':
            self.port = 443

        print "host = %s, port = %s" % (self.host, self.port)

        arg_match = self.xml_arg_re.match(command_string)

        return "%s -o %s -f xml \n" % (command_string, self._output_file_path)

    def setHost(self):
        pass


def createPlugin():
    return WapitiPlugin()

if __name__ == '__main__':
    parser = WapitiXmlParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print item
