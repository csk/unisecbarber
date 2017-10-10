#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import re
from models import (Result,
        Host,
        Interface,
        Service,
        Vuln,
        VulnWeb,
        Credential,
        Note        )
from result import ResultBuilder
from common import factory

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

class PluginBase(object):
    # TODO: Add class generic identifier
    class_signature = "PluginBase"

    def __init__(self):

        # Must be unique. Check that there is not
        # an existant plugin with the same id.
        # TODO: Make script that list current ids.
        self.data_path = CONF.getDataPath()
        self.id = None
        self._rid = id(self)
        self.version = None
        self.name = None
        self.description = ""
        self._command_regex = None
        self._output_file_path = None
        self.framework_version = None
        self._completition = {}
        self._new_elems = []
        self._settings = {}

        self.result_builder = ResultBuilder()

        self.debug = False

    def get_result(self):
        return self.result_builder.get_result()

    def has_custom_output(self):
        return bool(self._output_file_path)

    def get_custom_file_path(self):
        return self._output_file_path

    def getSettings(self):
        for param, (param_type, value) in self._settings.iteritems():
            yield param, value

    def get_ws(self):
        return '__unisecbarber__'

    def getSetting(self, name):
        setting_type, value = self._settings[name]
        return value

    def addSetting(self, param, param_type, value):
        self._settings[param] = param_type, value

    def updateSettings(self, new_settings):
        for name, value in new_settings.iteritems():
            if name in self._settings:
                setting_type, curr_value = self._settings[name]
                self._settings[name] = setting_type, setting_type(value)

    def canParseCommandString(self, current_input):
        """
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        return (self._command_regex is not None and
                self._command_regex.match(current_input.strip()) is not None)

    def getCompletitionSuggestionsList(self, current_input):
        """
        This method can be overriden in the plugin implementation
        if a different kind of check is needed
        """
        words = current_input.split(" ")
        cword = words[len(words) - 1]

        options = {}
        for k, v in self._completition.iteritems():
            if re.search(str("^" + cword), k, flags=re.IGNORECASE):
                options[k] = v

        return options

    def process_output(self, term_output):
        output = term_output
        if self.has_custom_output() and os.path.isfile(self.get_custom_file_path()):
            output = open(self.get_custom_file_path(), 'r').read()
        self.parseOutputString(output)

    def parseOutputString(self, output):
        """
        This method must be implemented.
        This method will be called when the command finished executing and
        the complete output will be received to work with it
        Using the output the plugin can create and add hosts, interfaces,
        services, etc.
        """
        pass

    def processCommandString(self, username, current_path, command_string):
        """
        With this method a plugin can add aditional arguments to the
        command that it's going to be executed.
        """
        return None

    def createAndAddHost(self, name, os="unknown"):
        host_obj = factory.createModelObject(
            Host.class_signature,
            name, os=os, parent_id=None)

        self.result_builder.add_item(host_obj)
        
        return host_obj.get_id()

    def createAndAddInterface(
        self, host_id, name="", mac="00:00:00:00:00:00",
        ipv4_address="0.0.0.0", ipv4_mask="0.0.0.0", ipv4_gateway="0.0.0.0",
        ipv4_dns=[], ipv6_address="0000:0000:0000:0000:0000:0000:0000:0000",
        ipv6_prefix="00",
        ipv6_gateway="0000:0000:0000:0000:0000:0000:0000:0000", ipv6_dns=[],
        network_segment="", hostname_resolution=[]):

        # hostname_resolution must be a list. Many plugins are passing a string
        # as argument causing errors in the WEB UI.
        if isinstance(hostname_resolution, str):
            hostname_resolution = [hostname_resolution]

        int_obj = factory.createModelObject(
            Interface.class_signature,
            name, mac=mac, ipv4_address=ipv4_address,
            ipv4_mask=ipv4_mask, ipv4_gateway=ipv4_gateway, ipv4_dns=ipv4_dns,
            ipv6_address=ipv6_address, ipv6_prefix=ipv6_prefix,
            ipv6_gateway=ipv6_gateway, ipv6_dns=ipv6_dns,
            network_segment=network_segment,
            hostnames=hostname_resolution, parent_id=host_id)

        self.result_builder.add_item(int_obj)

        return int_obj.get_id()


    def createAndAddServiceToInterface(self, host_id, interface_id, name,
                                       protocol="tcp?", ports=[],
                                       status="running", version="unknown",
                                       description=""):

        serv_obj = factory.createModelObject(
            Service.class_signature,
            name, protocol=protocol, ports=ports, status=status,
            version=version, description=description, parent_id=interface_id)

        self.result_builder.add_item(serv_obj)

        return serv_obj.get_id()

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=[],
                               severity="", resolution=""):

        vuln_obj = factory.createModelObject(
            Vuln.class_signature,
            name, desc=desc, refs=ref, severity=severity, resolution=resolution,
            confirmed=False, parent_id=host_id)

        self.result_builder.add_item(vuln_obj)

        return vuln_obj.get_id()

    def createAndAddVulnToInterface(self, host_id, interface_id, name,
                                    desc="", ref=[], severity="",
                                    resolution=""):

        vuln_obj = factory.createModelObject(
            Vuln.class_signature,
            name, desc=desc, refs=ref, severity=severity, resolution=resolution,
            confirmed=False, parent_id=interface_id)

        self.result_builder.add_item(vuln_obj)

        return vuln_obj.get_id()

    def createAndAddVulnToService(self, host_id, service_id, name, desc="",
                                  ref=[], severity="", resolution=""):

        vuln_obj = factory.createModelObject(
            Vuln.class_signature,
            name, desc=desc, refs=ref, severity=severity, resolution=resolution,
            confirmed=False, parent_id=service_id)

        self.result_builder.add_item(vuln_obj)

        return vuln_obj.get_id()

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="",
                                     ref=[], severity="", resolution="",
                                     website="", path="", request="",
                                     response="", method="", pname="",
                                     params="", query="", category=""):
        vulnweb_obj = factory.createModelObject(
            VulnWeb.class_signature,
            name, desc=desc, refs=ref, severity=severity, resolution=resolution,
            website=website, path=path, request=request, response=response,
            method=method, pname=pname, params=params, query=query,
            category=category, confirmed=False, parent_id=service_id)

        self.result_builder.add_item(vulnweb_obj)

        return vulnweb_obj.get_id()

    def createAndAddNoteToHost(self, host_id, name, text):

        note_obj = factory.createModelObject(
            Note.class_signature,
            name, text=text, parent_id=host_id)

        self.result_builder.add_item(note_obj)
        return note_obj.get_id()

    def createAndAddNoteToInterface(self, host_id, interface_id, name, text):

        note_obj = factory.createModelObject(
            Note.class_signature,
            name, text=text, parent_id=interface_id)

        self.result_builder.add_item(note_obj)
        return note_obj.get_id()

    def createAndAddNoteToService(self, host_id, service_id, name, text):

        note_obj = factory.createModelObject(
            Note.class_signature,
            name, text=text, parent_id=service_id)

        self.result_builder.add_item(note_obj)
        return note_obj.get_id()

    def createAndAddNoteToNote(self, host_id, service_id, note_id, name, text):

        note_obj = factory.createModelObject(
            Note.class_signature,
            name, text=text, parent_id=note_id)

        self.result_builder.add_item(note_obj)
        return note_obj.get_id()

    def createAndAddCredToService(self, host_id, service_id, username,
                                  password):

        cred_obj = factory.createModelObject(
            Credential.class_signature,
            username, password=password, parent_id=service_id)

        self.result_builder.add_item(cred_obj)
        return cred_obj.get_id()


class PluginTerminalOutput(PluginBase):
    def __init__(self):
        super(PluginTerminalOutput, self).__init__()

    def process_output(self, term_output):
        self.parseOutputString(term_output)
