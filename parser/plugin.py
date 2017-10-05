#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import multiprocessing
import os
import re
import Queue
import traceback
import hashlib
import json
from models import (Host,
        Interface,
        Service,
        Vuln,
        VulnWeb,
        Credential,
        Note,
        Command
        )
from modelactions import modelactions
from common import merge_two_dicts

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
        self._pending_actions = Queue.Queue()
        self._settings = {}
        
        self.parsed_objs = {}

        self.debug = False

    def has_custom_output(self):
        return bool(self._output_file_path)

    def get_custom_file_path(self):
        return self._output_file_path

    def getSettings(self):
        for param, (param_type, value) in self._settings.iteritems():
            yield param, value

    def get_ws(self):
        return '__sectool__'

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

    def processOutput(self, term_output):
        output = term_output
        if self.has_custom_output() and os.path.isfile(self.get_custom_file_path()):
            output = open(self.get_custom_file_path(), 'r').read()
        self.parseOutputString(output)

    def processReport(self, filepath):
        if os.path.isfile(filepath):
            output = open(filepath, 'r').read()
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

    def __addToList(self, obj):
        """
        Adds a new pending action to the queue
        Action is build with generic args tuple.
        The caller of this function has to build the action in the right
        way since no checks are preformed over args
        """
        if obj['type'] == Host.class_signature:
            self.parsed_objs[obj['name']] = obj
        elif obj['type'] == Interface.class_signature:
            host = obj['host_id']
            del obj['host_id']
            if not obj['type'] in self.parsed_objs[host['name']]:
                self.parsed_objs[host['name']][obj['type']] = {}
            self.parsed_objs[host['name']][obj['type']][obj['mac']] = obj
        elif obj['type'] == Service.class_signature:
            iface = obj['interface_id']
            del obj['interface_id']
            if not obj['type'] in self.parsed_objs[iface['name']][Interface.class_signature][iface['mac']]:
                self.parsed_objs[iface['name']][Interface.class_signature][iface['mac']][obj['type']] = {}
            hsh = hashlib.md5(json.dumps(obj, sort_keys=True)).hexdigest()
            self.parsed_objs[iface['name']][Interface.class_signature][iface['mac']][obj['type']][hsh] = obj


    def createAndAddHost(self, name, os="unknown"):
        obj =  {
            'type': Host.class_signature,
            'name': name,
            'os': os
        }

        if self.debug:
            msg="""
            Host.class_signature: '%s'
            name: '%s'
            os: '%s'
            """ % (Host.class_signature, name, os)
            self.log("[%s] %s" % (modelactions.ADDHOST, msg), 'DEBUG')
        self.__addToList(obj)
        return obj

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

        obj = {
            'type': Interface.class_signature,
            'name': name,
            'mac': mac,
            'ipv4_address': ipv4_address,
            'ipv4_mask': ipv4_mask,
            'ipv4_gateway': ipv4_gateway,
            'ipv4_dns': ipv4_dns,
            'ipv6_address': ipv6_address,
            'ipv6_prefix': ipv6_prefix,
            'ipv6_gateway': ipv6_gateway,
            'ipv6_dns': ipv6_dns,
            'network_segment': network_segment,
            'host_id': host_id
        }

        self.__addToList(obj)
        return obj


    def createAndAddServiceToInterface(self, host_id, interface_id, name,
                                       protocol="tcp?", ports=[],
                                       status="running", version="unknown",
                                       description=""):

        obj = {
            'type': Service.class_signature,
            'name': name,
            'protocol': protocol,
            'ports': ports,
            'status': status,
            'version': version,
            'description': description,
            'interface_id': interface_id
        }

        self.__addToList(obj)
        return obj

    def createAndAddVulnToHost(self, host_id, name, desc="", ref=[],
                               severity="", resolution=""):

        # vuln_obj = model.common.factory.createModelObject(
        #     Vuln.class_signature,
        #     name, desc=desc, refs=ref, severity=severity, resolution=resolution,
        #     confirmed=False, parent_id=host_id)

        # vuln_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDVULNHOST, host_id, vuln_obj)
        # return vuln_obj.getID()
        pass

    def createAndAddVulnToInterface(self, host_id, interface_id, name,
                                    desc="", ref=[], severity="",
                                    resolution=""):

        # vuln_obj = model.common.factory.createModelObject(
        #     Vuln.class_signature,
        #     name, desc=desc, refs=ref, severity=severity, resolution=resolution,
        #     confirmed=False, parent_id=interface_id)

        # vuln_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDVULNINT, host_id, interface_id, vuln_obj)
        # return vuln_obj.getID()
        pass

    def createAndAddVulnToService(self, host_id, service_id, name, desc="",
                                  ref=[], severity="", resolution=""):

        # vuln_obj = model.common.factory.createModelObject(
        #     Vuln.class_signature,
        #     name, desc=desc, refs=ref, severity=severity, resolution=resolution,
        #     confirmed=False, parent_id=service_id)

        # vuln_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDVULNSRV, host_id, service_id, vuln_obj)
        # return vuln_obj.getID()
        pass

    def createAndAddVulnWebToService(self, host_id, service_id, name, desc="",
                                     ref=[], severity="", resolution="",
                                     website="", path="", request="",
                                     response="", method="", pname="",
                                     params="", query="", category=""):
        # vulnweb_obj = model.common.factory.createModelObject(
        #     VulnWeb.class_signature,
        #     name, desc=desc, refs=ref, severity=severity, resolution=resolution,
        #     website=website, path=path, request=request, response=response,
        #     method=method, pname=pname, params=params, query=query,
        #     category=category, confirmed=False, parent_id=service_id)

        # vulnweb_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDVULNWEBSRV, host_id, service_id, vulnweb_obj)
        # return vulnweb_obj.getID()
        pass

    def createAndAddNoteToHost(self, host_id, name, text):

        # note_obj = model.common.factory.createModelObject(
        #     Note.class_signature,
        #     name, text=text, parent_id=host_id)

        # note_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDNOTEHOST, host_id, note_obj)
        # return note_obj.getID()
        pass

    def createAndAddNoteToInterface(self, host_id, interface_id, name, text):

        # note_obj = model.common.factory.createModelObject(
        #     Note.class_signature,
        #     name, text=text, parent_id=interface_id)

        # note_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDNOTEINT, host_id, interface_id, note_obj)
        # return note_obj.getID()
        pass

    def createAndAddNoteToService(self, host_id, service_id, name, text):

        # note_obj = model.common.factory.createModelObject(
        #     Note.class_signature,
        #     name, text=text, parent_id=service_id)

        # note_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDNOTESRV, host_id, service_id, note_obj)
        # return note_obj.getID()
        pass

    def createAndAddNoteToNote(self, host_id, service_id, note_id, name, text):

        # note_obj = model.common.factory.createModelObject(
        #     Note.class_signature,
        #     name, text=text, parent_id=note_id)

        # note_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDNOTENOTE, host_id, service_id, note_id, note_obj)
        # return note_obj.getID()
        pass

    def createAndAddCredToService(self, host_id, service_id, username,
                                  password):

        # cred_obj = model.common.factory.createModelObject(
        #     Credential.class_signature,
        #     username, password=password, parent_id=service_id)

        # cred_obj._metadata.creator = self.id
        # self.__addPendingAction(modelactions.ADDCREDSRV, host_id, service_id, cred_obj)
        # return cred_obj.getID()
        pass


class PluginTerminalOutput(PluginBase):
    def __init__(self):
        super(PluginTerminalOutput, self).__init__()

    def processOutput(self, term_output):
        self.parseOutputString(term_output)


class PluginCustomOutput(PluginBase):
    def __init__(self):
        super(PluginCustomOutput, self).__init__()

    def processOutput(self, term_output):
        # we discard the term_output since it's not necessary
        # for this type of plugins
        self.processReport(self._output_file_path)
