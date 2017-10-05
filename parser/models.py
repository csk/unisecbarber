#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import glob
import os
import sys
from time import time
import traceback
from threading import Lock

from common import (force_unique,
                      get_hash,
                      get_host_properties,
                      get_interface_properties,
                      get_service_properties,
                      get_vuln_properties,
                      get_vuln_web_properties,
                      get_note_properties,
                      get_credential_properties,
                      get_command_properties)

from functools import wraps

from utils.logs import getLogger


def log(msg ,level = "INFO"):
    """
    This api will log the text in the GUI console without the level
    it will also log to a file with the corresponding level
    if logger was configured that way
    """
    levels = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
        "NOTSET": logging.NOTSET
    }
    level = levels.get(level, logging.NOTSET)
    getLogger().log(level, msg)

def devlog(msg):
    """
    If DEBUG is set it will print information directly to stdout
    """
    getLogger().debug(msg)



def _flatten_dictionary(dictionary):
    """Given a dictionary with dictionaries inside, create a new flattened
    dictionary from that one and return it.

    It's not as general as it sounds. Do not use without looking at the
    implementation.
    """
    flattened_dict = {}
    if dictionary.get('_id'):
        flattened_dict[u'_id'] = dictionary['_id']
    if dictionary.get('id'):
        flattened_dict[u'id'] = dictionary['id']
    for k, v in dictionary.get('value', {}).items():
        if k != '_id':  # this is the couch id, which we have saved on 'id'
            flattened_dict[k] = v
    return flattened_dict


# NOTE: the whole 'which arguments are mandatory and which type should they be"
# should probably be reviewed in a nice developmet meeting where
# I think there are several # discrepancies between the models here,
# those on the server and the parameters the apis specify,
# and this leads to potential dissaster. Remember params?
class ModelBase(object):
    """A model for all the Faraday Objects.
    There should be a one to one correspondance with the jsons the faraday
    server gives through apis and the classes inheriting from this one.
    That is: you can view this classes as an python-object representation
    of the server's json or viceversa.

    As all the classes take the obj dictionary as an mandatory parameter.
    The obj dictionary contains the information of the object we need to create
    an instance of. To specify a default argument for the objects attributes,
    use the .get method for dictionaries. Try to specifiy a default value that
    matches the type of the value you expect.

    All of the values used from the obj dictionary that are set to be
    non-nullable on the server's models (server/models.py) should be given a
    sane default argument, EXCEPT for those where we can't provide a one.
    For example, we can't provide a sane default argument for ID, that should be
    given to us and indeed raise an exception if it wasn't. We can provide
    a default argument for 'description': if nothing came, assume empty string,
    """
    def __init__(self, obj, workspace_name):
        self._workspace_name = workspace_name
        self._server_id = obj.get('_id', '')
        self.id = obj.get('id', '')
        self.name = obj.get('name')
        self.description = obj.get('description', "")
        self.owned = obj.get('owned', False)
        self.owner = obj.get('owner', '')
        self._metadata = obj.get('metadata', Metadata(self.owner))
        self.updates = []

    def setID(self, parent_id, *args):
        if  self.id and self.id != -1:
            return None
        objid = get_hash(args)
        if parent_id:
            objid = '.'.join([parent_id, objid])
        self.id = objid

    @staticmethod
    def publicattrsrefs():
        return {'Description': 'description',
                'Name': 'name',
                'Owned': 'owned'}

    def defaultValues(self):
        return [-1, 0, '', 'None', 'none', 'unknown', None, [], {}]

    def addUpdate(self, newModelObject):
        conflict = False
        for k, v in diff.getPropertiesDiff().items():
            setattr(self, attribute, prop_update)
        return conflict

    def getUpdates(self):
        return self.updates

    def updateResolved(self, update):
        self.updates.remove(update)

    def getOwner(self): return self.owner
    def isOwned(self): return self.owned
    def getName(self): return self.name
    def getMetadata(self): return self._metadata
    def getDescription(self): return self.description


class Host(ModelBase):
    """A simple Host class. Should implement all the methods of the
    Host object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Host'

    def __init__(self, host, workspace_name):
        ModelBase.__init__(self, host, workspace_name)
        self.default_gateway = host.get('default_gateway')
        self.os = host.get('os') if host.get('os') else 'unknown'
        self.vuln_amount = int(host.get('vulns', 0))

    def setID(self, _):
        # empty arg so as to share same interface as other classes' generateID
        ModelBase.setID(self, '', self.name)

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Operating System' : 'os'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, os=None, owned=None):
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if os is not None:
            self.os = os
        if owned is not None:
            self.owned = owned

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def getOS(self): return self.os
    def getVulnAmount(self): return self.vuln_amount
    def getID(self): return self.id
    def getDefaultGateway(self): return self.default_gateway
    def getVulns(self):
        return get_all_vulns(self._workspace_name, hostid=self._server_id)
    def getInterface(self, interface_couch_id):
        service = get_interfaces(self._workspace_name, couchid=interface_couch_id)
        return service[0]
    def getAllInterfaces(self):
        return get_interfaces(self._workspace_name, host=self._server_id)
    def getServices(self):
        return get_services(self._workspace_name, hostid=self._server_id)


class Interface(ModelBase):
    """A simple Interface class. Should implement all the methods of the
    Interface object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Interface'

    def __init__(self, interface, workspace_name):
        ModelBase.__init__(self, interface, workspace_name)
        self.hostnames = interface.get('hostnames', [])

        # NOTE. i don't know why this is like this
        # probably a remnant of the old faraday style classes
        try:
            self.ipv4 = interface['ipv4']
            self.ipv6 = interface['ipv6']
        except KeyError:
            self.ipv4 = {'address': interface['ipv4_address'],
                         'gateway': interface['ipv4_gateway'],
                         'mask': interface['ipv4_mask'],
                         'DNS': interface['ipv4_dns']}
            self.ipv6 = {'address': interface['ipv6_address'],
                         'gateway': interface['ipv6_gateway'],
                         'prefix': interface['ipv6_prefix'],
                         'DNS': interface['ipv6_dns']}
        self.mac = interface.get('mac')
        self.network_segment = interface.get('network_segment')
        self.ports = interface.get('ports')

        self.amount_ports_opened   = 0
        self.amount_ports_closed   = 0
        self.amount_ports_filtered = 0

    def setID(self, parent_id):
        try:
            ipv4_address = self.ipv4_address
            ipv6_address = self.ipv6_address
        except AttributeError:
            ipv4_address = self.ipv4['address']
            ipv6_address = self.ipv6['address']

        ModelBase.setID(self, parent_id, self.network_segment, ipv4_address, ipv6_address)

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'MAC Address' : 'mac',
            'IPV4 Settings' : 'ipv4',
            'IPV6 Settings' : 'ipv6',
            'Network Segment' : 'network_segment',
            'Hostnames' : 'hostnames'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, hostnames=None, mac=None, ipv4=None, ipv6=None,
                         network_segment=None, amount_ports_opened=None, amount_ports_closed=None,
                         amount_ports_filtered=None, owned=None):

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if hostnames is not None:
            self.hostnames = hostnames
        if mac is not None:
            self.mac = mac
        if ipv4 is not None:
            self.ipv4 = ipv4
        if ipv6 is not None:
            self.ipv6 = ipv6
        if network_segment is not None:
            self.network_segment = network_segment
        if amount_ports_opened is not None:
            self.setPortsOpened(amount_ports_opened)
        if amount_ports_closed is not None:
            self.setPortsClosed(amount_ports_closed)
        if amount_ports_filtered is not None:
            self.setPortsFiltered(amount_ports_filtered)
        if owned is not None:
            self.owned = owned

    def setPortsOpened(self, ports_opened):
        self.amount_ports_opened   = ports_opened

    def setPortsClosed(self, ports_closed):
        self.amount_ports_closed   = ports_closed

    def setPortsFiltered(self, ports_filtered):
        self.amount_ports_filtered = ports_filtered

    def __str__(self): return "{0}".format(self.name)
    def getID(self): return self.id
    def getHostnames(self): return self.hostnames
    def getIPv4(self): return self.ipv4
    def getIPv6(self): return self.ipv6
    def getIPv4Address(self): return self.ipv4['address']
    def getIPv4Mask(self): return self.ipv4['mask']
    def getIPv4Gateway(self): return self.ipv4['gateway']
    def getIPv4DNS(self): return self.ipv4['DNS']
    def getIPv6Address(self): return self.ipv6['address']
    def getIPv6Gateway(self): return self.ipv6['gateway']
    def getIPv6DNS(self): return self.ipv6['DNS']
    def getMAC(self): return self.mac
    def getNetworkSegment(self): return self.network_segment

    def getService(self, service_couch_id):
        return get_service(self._workspace_name, service_couch_id)
    def getAllServices(self):
        return get_services(self._workspace_name, interface=self._server_id)
    def getVulns(self):
        return get_all_vulns(self._workspace_name, interfaceid=self._server_id)


class Service(ModelBase):
    """A simple Service class. Should implement all the methods of the
    Service object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Service'

    def __init__(self, service, workspace_name):
        ModelBase.__init__(self, service, workspace_name)
        self.protocol = service['protocol']
        self.ports =  [int(port) for port in service['ports']]
        self.version = service['version']
        self.status = service['status']
        self.vuln_amount = int(service.get('vulns', 0))

    def setID(self, parent_id):
        # TODO: str from list? ERROR MIGRATION NEEDED
        ports = ':'.join(str(self.ports))
        ModelBase.setID(self, parent_id, self.protocol, ports)

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Ports' : 'ports',
            'Protocol' : 'protocol',
            'Status' : 'status',
            'Version' : 'version'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, protocol=None, ports=None,
                          status=None, version=None, owned=None):
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if protocol is not None:
            self.protocol = protocol
        if ports is not None:
            self.ports = ports
        if status is not None:
            self.status = status
        if version is not None:
            self.version = version
        if owned is not None:
            self.owned = owned

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def getID(self): return self.id
    def getStatus(self): return self.status
    def getPorts(self): return self.ports  # this is a list of one element in faraday
    def getVersion(self): return self.version
    def getProtocol(self): return self.protocol
    def isOwned(self): return self.owned
    def getVulns(self): return get_all_vulns(self._workspace_name, serviceid=self._server_id)


class Vuln(ModelBase):
    """A simple Vuln class. Should implement all the methods of the
    Vuln object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Vulnerability'

    def __init__(self, vuln, workspace_name):
        ModelBase.__init__(self, vuln, workspace_name)
        # this next two lines are stupid but so is life so you should get used to it :)
        self.description = vuln['desc']
        self.desc = vuln['desc']
        self.data = vuln.get('data')
        self.severity = self.standarize(vuln['severity'])
        self.refs = vuln.get('refs') or []
        self.confirmed = vuln.get('confirmed', False)
        self.resolution = vuln.get('resolution')
        self.status = vuln.get('status', "opened")
        self.policyviolations = vuln.get('policyviolations', list())

    def setID(self, parent_id):
        ModelBase.setID(self, parent_id, self.name, self.description)

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Data' : 'data',
            'Severity' : 'severity',
            'Refs' : 'refs',
            'Resolution': 'resolution',
            'Status': 'status'
        })
        return publicattrs

    def standarize(self, severity):
        # Transform all severities into lower strings
        severity = str(severity).lower()
        # If it has info, med, high, critical in it, standarized to it:


        def align_string_based_vulns(severity):
            severities = ['info','low', 'med', 'high', 'critical']
            for sev in severities:
                if severity[0:3] in sev:
                    return sev
            return severity

        severity = align_string_based_vulns(severity)

        # Transform numeric severity into desc severity
        numeric_severities = { '0' : 'info',
                                 '1' : 'low',
                                 '2' : 'med',
                                 '3' : 'high',
                                 "4" : 'critical' }


        if not severity in numeric_severities.values():
            severity = numeric_severities.get(severity, 'unclassified')

        return severity

    def updateAttributes(self, name=None, desc=None, data=None,
                         severity=None, resolution=None, refs=None, status=None, policyviolations=None):
        if name is not None:
            self.name = name
        if desc is not None:
            self.desc = desc
        if data is not None:
            self.data = data
        if resolution is not None:
            self.resolution = resolution
        if severity is not None:
            self.severity = self.standarize(severity)
        if refs is not None:
            self.refs = refs
        if status is not None:
            self.setStatus(status)
        if policyviolations is not None:
            self.policyviolations = policyviolations

    def getID(self): return self.id
    def getDesc(self): return self.desc
    def getData(self): return self.data
    def getSeverity(self): return self.severity
    def getRefs(self): return self.refs
    def getConfirmed(self): return self.confirmed
    def getResolution(self): return self.resolution
    def getStatus(self): return self.status
    def getPolicyViolations(self): return self.policyviolations

    def setStatus(self, status):
        self.status = status


class VulnWeb(Vuln):
    """A simple VulnWeb class. Should implement all the methods of the
    VulnWeb object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'VulnerabilityWeb'

    def __init__(self, vuln_web, workspace_name):
        Vuln.__init__(self, vuln_web, workspace_name)
        self.path = vuln_web.get('path')
        self.website = vuln_web.get('website')
        self.request = vuln_web.get('request')
        self.response = vuln_web.get('response')
        self.method = vuln_web.get('method')
        self.pname = vuln_web.get('pname')
        self.params = vuln_web.get('params')
        self.query = vuln_web.get('query')
        self.resolution = vuln_web.get('resolution')
        self.attachments = vuln_web.get('_attachments')
        self.hostnames = vuln_web.get('hostnames')
        self.impact = vuln_web.get('impact')
        self.service = vuln_web.get('service')
        self.tags = vuln_web.get('tags')
        self.target = vuln_web.get('target')
        self.parent = vuln_web.get('parent')
        self.policyviolations = vuln_web.get('policyviolations', list())

    def setID(self, parent_id):
        ModelBase.setID(self, parent_id, self.name, self.website, self.path, self.description)

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Data' : 'data',
            'Severity' : 'severity',
            'Refs' : 'refs',
            'Path' : 'path',
            'Website' : 'website',
            'Request' : 'request',
            'Response' : 'response',
            'Method' : 'method',
            'Pname' : 'pname',
            'Params' : 'params',
            'Query' : 'query',
            'Status': 'status'})
        return publicattrs

    def updateAttributes(self, name=None, desc=None, data=None, website=None, path=None, refs=None,
                        severity=None, resolution=None, request=None,response=None, method=None,
                        pname=None, params=None, query=None, category=None, status=None, policyviolations=None):

        super(self.__class__, self).updateAttributes(name, desc, data, severity, resolution, refs, status)

        if website is not None:
            self.website = website
        if path is not None:
            self.path = path
        if request is not None:
            self.request = request
        if response is not None:
            self.response = response
        if method is not None:
            self.method = method
        if pname is not None:
            self.pname = pname
        if params is not None:
            self.params = params
        if query is not None:
            self.query = query
        if category is not None:
            self.category = category
        if policyviolations is not None:
            self.policyviolations = policyviolations

    def getDescription(self): return self.description
    def getPath(self): return self.path
    def getWebsite(self): return self.website
    def getRequest(self): return self.request
    def getResponse(self): return self.response
    def getMethod(self): return self.method
    def getPname(self): return self.pname
    def getParams(self): return self.params
    def getQuery(self): return self.query
    def getResolution(self): return self.resolution
    def getAttachments(self): return self.attachments
    def getEaseOfResolution(self): return self.easeofresolution
    def getHostnames(self): return self.hostnames
    def getImpact(self): return self.impact
    def getService(self): return self.service
    def getStatus(self): return self.status
    def getTags(self): return self.tags
    def getTarget(self): return self.target
    def getParent(self): return self.parent
    def getPolicyViolations(self): return self.policyviolations


class Note(ModelBase):
    class_signature = 'Note'

    def __init__(self, note, workspace_name):
        ModelBase.__init__(self, note, workspace_name)
        self.text = note['text']

    def setID(self, parent_id):
        ModelBase.setID(self, parent_id, self.name, self.text)

    def updateAttributes(self, name=None, text=None):
        if name is not None:
            self.name = name
        if text is not None:
            self.text = text

    def getID(self): return self.id
    def getDescription(self): return self.description
    def getText(self): return self.text

class Credential(ModelBase):
    class_signature = "Cred"

    def __init__(self, credential, workspace_name):
        ModelBase.__init__(self, credential, workspace_name)
        try:
            self.username = credential['username']
        except KeyError:
            self.username = credential['name']

        self.password = credential['password']

    def setID(self, parent_id):
        ModelBase.setID(self, parent_id, self.name, self.username, self.password)

    def updateAttributes(self, username=None, password=None):
        if username is not None:
            self.username =username
        if password is not None:
            self.password = password

    def getID(self): return self.id
    def getUsername(self): return self.username
    def getPassword(self): return self.password

class Command:
    class_signature = 'CommandRunInformation'
    def __init__(self, command, workspace_name):
        self._workspace_name = workspace_name
        self.id = command['id']
        self.command = command['command']
        self.duration = command['duration']
        self.hostname = command['hostname']
        self.ip = command['ip']
        self.itime = command['itime']
        self.params = command['params']
        self.user = command['user']
        self.workspace = command['workspace']

    def getID(self): return self.id
    def getCommand(self): return self.command
    def getDuration(self): return self.duration
    def getHostname(self): return self.hostname
    def getIP(self): return self.ip
    def getItime(self): return self.itime
    def getParams(self): return self.params
    def getUser(self): return self.user

class MetadataUpdateActions(object):
    """Constants for the actions made on the update"""
    UNDEFINED   = -1
    CREATE      = 0
    UPDATE      = 1


class Metadata(object):
    """To save information about the modification of ModelObjects.
       All members declared public as this is only a wrapper"""

    class_signature = "Metadata"

    def __init__(self, user):
        self.creator        = user
        self.owner          = user
        self.create_time    = time()
        self.update_time    = time()
        self.update_user    = user
        self.update_action  = MetadataUpdateActions.CREATE
        self.update_controller_action = self.__getUpdateAction()
        self.command_id = ''

    def toDict(self):
        return self.__dict__

    def fromDict(self, dictt):
        for k, v in dictt.items():
            setattr(self, k, v)
        return self

    def update(self, user, action = MetadataUpdateActions.UPDATE):
        """Update the local metadata giving a user and an action.
        Update time gets modified to the current system time"""
        self.update_user = user
        self.update_time = time()
        self.update_action = action

        self.update_controller_action = self.__getUpdateAction()

    def __getUpdateAction(self):
        """This private method grabs the stackframes in look for the controller
        call that generated the update"""

        l_strace = traceback.extract_stack(limit = 10)
        controller_funcallnames = [ x[2] for x in l_strace if "controller" in x[0] ]

        if controller_funcallnames:
            return "ModelControler." +  " ModelControler.".join(controller_funcallnames)
        return "No model controller call"

# NOTE: uncomment for test
# class SillyHost():
#     def __init__(self) :
#         import random; self.id = random.randint(0, 1000)
#         self.os = "Windows"
#     def getID(self): return self.id
#     def getOS(self): return self.os
#     def getDefaultGateway(self): return '192.168.1.1'
#     def getDescription(self): return "a description"
#     def getName(self): return "my name"
#     def isOwned(self): return False
#     def getOwner(self): return False
#     def getMetadata(self): return {'stuff': 'gives other stuff'}
