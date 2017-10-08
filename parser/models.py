#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from common import get_hash
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

def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z


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

class Result(object):

    def __init__(self):
        self.hosts = []
        self.meta = dict()

    def add_host(self, host):
        self.hosts.append(host)
    
    def get_hosts(self):
        return self.hosts

    def remove_host(self):
        return self.hosts

    def jsonable(self):
        return dict(hosts=self.hosts, meta=self.meta)


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
    def __init__(self, obj):
        self.id = obj.get('id', '')
        self.name = obj.get('name')
        self.description = obj.get('description', "")
        self._metadata = obj.get('metadata', None)

    def set_id(self, parent_id, *args):
        if  self.id and self.id != -1:
            return None
        objid = get_hash(args)
        if parent_id:
            objid = '.'.join([parent_id, objid])
        self.id = objid

    def defaultValues(self):
        return [-1, 0, '', 'None', 'none', 'unknown', None, [], {}]

    def jsonable(self):
        return dict(
            name=self.name,
            description=self.description
            )


class Host(ModelBase):
    """A simple Host class. Should implement all the methods of the
    Host object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Host'

    def __init__(self, host):
        ModelBase.__init__(self, host)
        self.default_gateway = host.get('default_gateway')
        self.os = host.get('os') if host.get('os') else 'unknown'
        self.vuln_amount = int(host.get('vulns', 0))

        self.interfaces = []
        self.vulns = []
        self.creds = []
        self.services = []
        self.notes = []

    def set_id(self, _):
        # empty arg so as to share same interface as other classes' generateID
        ModelBase.set_id(self, '', self.name)

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    
    def get_id(self): return self.id
    
    def add_interface(self, iface):
        return self.interfaces.append(iface)

    def add_vuln(self, vuln):
        return self.vulns.append(vuln)

    def add_cred(self, cred):
        return self.creds.append(cred)

    def add_service(self, service):
        return self.services.append(service)

    def add_note(self, note):
        return self.notes.append(note)

    def jsonable(self):
        fields = dict(
                    default_gateway=self.default_gateway,
                    os=self.os,
                    vuln_amount=self.vuln_amount,
                    interfaces=self.interfaces,
                    vulns=self.vulns,
                    creds=self.creds,
                    services=self.services,
                    notes=self.notes)
        return merge_two_dicts(super(Host,self).jsonable(),fields)




class Interface(ModelBase):
    """A simple Interface class. Should implement all the methods of the
    Interface object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Interface'

    def __init__(self, interface):
        ModelBase.__init__(self, interface)
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

        self.services = []
        self.vulns = []
        self.notes = []

    def set_id(self, parent_id):
        try:
            ipv4_address = self.ipv4_address
            ipv6_address = self.ipv6_address
        except AttributeError:
            ipv4_address = self.ipv4['address']
            ipv6_address = self.ipv6['address']

        ModelBase.set_id(self, parent_id, self.network_segment, ipv4_address, ipv6_address)

    def setPortsOpened(self, ports_opened):
        self.amount_ports_opened   = ports_opened

    def setPortsClosed(self, ports_closed):
        self.amount_ports_closed   = ports_closed

    def setPortsFiltered(self, ports_filtered):
        self.amount_ports_filtered = ports_filtered

    def __str__(self): return "{0}".format(self.name)
    def get_id(self): return self.id

    def get_ipv4_address(self): return self.ipv4['address']
    def get_ipv4_mask(self): return self.ipv4['mask']
    def get_ipv4_gateway(self): return self.ipv4['gateway']
    def get_ipv4_dns(self): return self.ipv4['DNS']

    def get_ipv6_address(self): return self.ipv6['address']
    def get_ipv6_gateway(self): return self.ipv6['gateway']
    def get_ipv6_dns(self): return self.ipv6['DNS']

    def add_service(self, service):
        return self.services.append(service)

    def add_vuln(self, vuln):
        return self.vulns.append(vuln)

    def add_note(self, note):
        return self.notes.append(note)

    def jsonable(self):
        fields=dict(
                    hostnames=self.hostnames,
                    mac=self.mac,
                    ipv4=self.ipv4,
                    ipv6=self.ipv6,
                    network_segment=self.network_segment,
                    amount_ports_opened=self.amount_ports_opened,
                    amount_ports_closed=self.amount_ports_closed,
                    amount_ports_filtered=self.amount_ports_filtered,
                    services=self.services,
                    vulns=self.vulns,
                    notes=self.notes,
            )
        return merge_two_dicts(super(Interface,self).jsonable(),fields)


class Service(ModelBase):
    """A simple Service class. Should implement all the methods of the
    Service object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Service'

    def __init__(self, service):
        ModelBase.__init__(self, service)
        self.protocol = service['protocol']
        self.ports =  [int(port) for port in service['ports']]
        self.version = service['version']
        self.status = service['status']
        self.vuln_amount = int(service.get('vulns', 0))

        self.vulns = []
        self.vuln_webs = []
        self.creds = []
        self.notes = []

    def set_id(self, parent_id):
        # TODO: str from list? ERROR MIGRATION NEEDED
        ports = ':'.join(str(self.ports))
        ModelBase.set_id(self, parent_id, self.protocol, ports)


    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def get_id(self): return self.id

    def add_vuln(self, vuln):
        return self.vulns.append(vuln)

    def add_vuln_web(self, vuln_web):
        return self.vuln_webs.append(vuln_web)

    def add_cred(self, cred):
        return self.creds.append(cred)

    def add_note(self, note):
        return self.notes.append(note)

    def jsonable(self):
        fields = dict(
                    protocol=self.protocol,
                    ports=self.ports,
                    status=self.status,
                    version=self.version,
                    vulns=self.vulns,
                    vuln_webs=self.vuln_webs,
                    creds=self.creds,
                    notes=self.notes
            )
        return merge_two_dicts(super(Service,self).jsonable(),fields)

class Vuln(ModelBase):
    """A simple Vuln class. Should implement all the methods of the
    Vuln object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Vulnerability'

    def __init__(self, vuln):
        ModelBase.__init__(self, vuln)
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

        self.notes = []

    def set_id(self, parent_id):
        ModelBase.set_id(self, parent_id, self.name, self.description)

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
                                 '4' : 'critical' }


        if not severity in numeric_severities.values():
            severity = numeric_severities.get(severity, 'unclassified')

        return severity

    def get_id(self): return self.id

    def add_note(self, note):
        return self.notes.append(note)

    def jsonable(self):
        fields = dict(
            desc=self.desc,
            data=self.data,
            severity=self.severity,
            refs=self.refs,
            confirmed=self.confirmed,
            resolution=self.resolution,
            status=self.status,
            policyviolations=self.policyviolations,
            notes=self.notes
            )
        return merge_two_dicts(super(Vuln,self).jsonable(),fields)

class VulnWeb(Vuln):
    """A simple VulnWeb class. Should implement all the methods of the
    VulnWeb object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'VulnerabilityWeb'

    def __init__(self, vuln_web):
        Vuln.__init__(self, vuln_web)
        self.path = vuln_web.get('path')
        self.website = vuln_web.get('website')
        self.request = vuln_web.get('request')
        self.response = vuln_web.get('response')
        self.method = vuln_web.get('method')
        self.pname = vuln_web.get('pname')
        self.params = vuln_web.get('params')
        self.query = vuln_web.get('query')
        self.attachments = vuln_web.get('_attachments')
        self.hostnames = vuln_web.get('hostnames')
        self.impact = vuln_web.get('impact')
        self.service = vuln_web.get('service')
        self.tags = vuln_web.get('tags')
        self.target = vuln_web.get('target')
        self.parent = vuln_web.get('parent')

    def set_id(self, parent_id):
        ModelBase.set_id(self, parent_id, self.name, self.website, self.path, self.description)

    def jsonable(self):
        fields = dict(
                path=self.path,
                website=self.website,
                request=self.request,
                response=self.response,
                method=self.method,
                pname=self.pname,
                params=self.params,
                query=self.query,
                attachments=self.attachments,
                hostnames=self.hostnames,
                impact=self.impact,
                service=self.service,
                tags=self.tags,
                target=self.target,
                parent=self.parent,
            )
        return merge_two_dicts(super(VulnWeb,self).jsonable(),fields)


class Note(ModelBase):
    class_signature = 'Note'

    def __init__(self, note):
        ModelBase.__init__(self, note)
        self.text = note['text']

        self.notes = []

    def set_id(self, parent_id):
        ModelBase.set_id(self, parent_id, self.name, self.text)

    def get_id(self): return self.id
    def getText(self): return self.text

    def jsonable(self):
        fields = dict(
                id=self.id,
                description=self.description,
                text=self.text,
                notes=self.notes
        )
        return merge_two_dicts(super(Note,self).jsonable(),fields)

class Credential(ModelBase):
    class_signature = "Cred"

    def __init__(self, credential):
        ModelBase.__init__(self, credential)
        try:
            self.username = credential['username']
        except KeyError:
            self.username = credential['name']

        self.password = credential['password']

    def set_id(self, parent_id):
        ModelBase.set_id(self, parent_id, self.name, self.username, self.password)

    def get_id(self): return self.id

    def jsonable(self):
        fields = dict(
                id=self.id,
                username=self.username,
                password=self.password
        )
        return merge_two_dicts(super(Credential,self).jsonable(),fields)

class Metadata(object):
    """To save information about the modification of ModelObjects.
       All members declared public as this is only a wrapper"""

    class_signature = "Metadata"

    def __init__(self, meta):
        self.id = meta['id']
        self.command = meta['command']
        self.duration = meta['duration']
        self.hostname = meta['hostname']
        self.ip = meta['ip']
        self.itime = meta['itime']
        self.params = meta['params']

    def to_dict(self):
        return self.__dict__

    def from_dict(self, dictt):
        for k, v in dictt.items():
            setattr(self, k, v)
        return self
    
    def jsonable(self):
        fields = dict(
            id=self.id,
            command=self.command,
            duration=self.duration,
            hostname=self.hostname,
            ip=self.ip,
            itime=self.itime,
            params=self.params
        )
        return fields


