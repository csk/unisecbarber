#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import hashlib
# from persistence.server.server_io_exceptions import MoreThanOneObjectFoundByID

def force_unique(lst):
    """Takes a list and return its only member if the list len is 1,
    None if list is empty or raises an MoreThanOneObjectFoundByID error
    if list has more than one element.
    """
    if len(lst) == 1:
        return lst[0]
    elif len(lst) == 0:
        return None
    else:
        raise Exception(lst)

def get_hash(parts):
    return hashlib.sha1("._.".join(parts)).hexdigest()

def get_object_properties(obj):
    # this sometimes is the metadata object and sometimes its a dictionary
    # a better fix awaits in a brighter future
    metadata = obj.getMetadata()
    if not isinstance(obj.getMetadata(), dict):
        metadata = metadata.toDict()

    return {'id': obj.getID(),
            'name': obj.getName(),
            'description': obj.getDescription(),
            'metadata': metadata,
            'owned': obj.isOwned(),
            'owner': obj.getOwner()
            }

def get_host_properties(host):
    host_dict = {'os': host.getOS(),
                 'default_gateway': host.getDefaultGateway()}
    host_dict.update(get_object_properties(host))
    return host_dict

def get_interface_properties(interface):
    interface_dict = {'mac': interface.getMAC(),
                      'hostnames': interface.getHostnames(),
                      'network_segment': interface.getNetworkSegment(),
                      'ipv4':  interface.getIPv4(),
                      'ipv6': interface.getIPv6()
                      }
    interface_dict.update(get_object_properties(interface))
    return interface_dict

def get_service_properties(service):
    service_dict = {'ports': service.getPorts(),
                    'protocol': service.getProtocol(),
                    'status': service.getStatus(),
                    'version': service.getVersion()
                    }
    service_dict.update(get_object_properties(service))
    return service_dict

def get_vuln_properties(vuln):
    vuln_dict = {'confirmed': vuln.getConfirmed(),
                 'data': vuln.getData(),
                 'refs': vuln.getRefs(),
                 'severity': vuln.getSeverity(),
                 'resolution': vuln.getResolution(),
                 'desc': vuln.getDesc(),
                 'status': vuln.getStatus()}
    vuln_dict.update(get_object_properties(vuln))
    return vuln_dict

def get_vuln_web_properties(vuln_web):
    vuln_web_dict = {'method': vuln_web.getMethod(),
                     'params': vuln_web.getParams(),
                     'request': vuln_web.getRequest(),
                     'response': vuln_web.getResponse(),
                     'website': vuln_web.getWebsite(),
                     'path': vuln_web.getPath(),
                     'pname': vuln_web.getPname(),
                     'query': vuln_web.getQuery(),
                     'status': vuln_web.getStatus()
                     }
    vuln_web_dict.update(get_object_properties(vuln_web))
    vuln_web_dict.update(get_vuln_properties(vuln_web))
    return vuln_web_dict

def get_note_properties(note):
    note_dict = {'text': note.getText()}
    note_dict.update(get_object_properties(note))
    return note_dict

def get_credential_properties(credential):
    cred_dict = {'username': credential.getUsername(),
                 'password': credential.getPassword()}
    cred_dict.update(get_object_properties(credential))
    return cred_dict

def get_command_properties(command):
    return {'id': command.getID(),
            'command': command.command,
            'user': command.user,
            'ip': command.ip,
            'hostname': command.hostname,
            'itime': command.itime,
            'duration': command.duration,
            'params': command.params}

def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z

# -------------------------------------------------------------------------------
# TODO: refactor this class to make it generic so this can be used also for plugins
#  then create a subclass and inherit the generic factory
class ModelObjectFactory(object):
    """
    Factory to creat any ModelObject type
    """
    def __init__(self):
        self._registered_objects = dict()

    def register(self, model_object):
        """registers a class into the factory"""
        self._registered_objects[model_object.class_signature] = model_object

    def listModelObjectClasses(self):
        """returns a list of registered classes"""
        return self._registered_objects.values()

    def getModelObjectClass(self, name):
        """get the class for a particular object typename"""
        return self._registered_objects[name]

    def listModelObjectTypes(self):
        """returns an array with object typenames the factory is able to create"""
        names = self._registered_objects.keys()
        names.sort()
        return names

    def generateID(self, classname, parent_id='', **objargs):
        """Given a classname, parent_id and necessary objargs, return the ID
        of the object.

        Necesary objargs vary according to the object:
        Host --> name
        Cred --> Name, password
        Note --> Name, text
        Service --> Protocol, ports
        Interface --> Network segments, ipv4_address, ipv6_address
        Vuln --> name, desc
        VulnWeb --> name, website
        """

        # see how nicely formated that dictionary is
        # it's a building about to go down on an eathquake!
        # let's try not to make that an analogy about my code, ok? thank you :)
        # appropiate_class = self._registered_objects[classname]
        # class_to_args = {'Host': (objargs.get('name'),),
        #                  'Cred': (objargs.get('name'), objargs.get('password')),
        #                  'Note': (objargs.get('name'),
        #                           objargs.get('text')),
        #                  'Service': (objargs.get('protocol'),
        #                              objargs.get('ports')),
        #                  'Interface': (objargs.get('network_segment'),
        #                                objargs.get('ipv4_address'),
        #                                objargs.get('ipv6_address')),
        #                  'Vulnerability': (objargs.get('name'),
        #                                    objargs.get('desc')),
        #                  'VulnerabilityWeb': (objargs.get('name'),
        #                                       objargs.get('website'))
        #                  }
        # try:
        #     id = appropiate_class.generateID(parent_id, *class_to_args[classname])
        # except KeyError:
        #     raise Exception("You've provided an invalid classname")
        # return id

    def createModelObject(self, classname, object_name, workspace_name=None, parent_id=None, **objargs):
        """Given a registered classname, create an object of name object_name and
        with the properties found on objargs. ID will be generated for you.

        If workspace_name is None, it will be inferred from the CONF module.
        parent_id should only be None if classname is 'Host' or maybe 'Note' or 'Credential'.
        """
        if not workspace_name:
            workspace_name = CONF.getLastWorkspace()
        if classname in self._registered_objects:
            if object_name is not None:
                objargs['name'] = object_name
                objargs['_id'] = -1  # they still don't have a server id
                objargs['id'] = -1 # we'll generate it after making sure the objects are okey
                tmpObj = self._registered_objects[classname](objargs, workspace_name)
                tmpObj.setID(parent_id)
                return tmpObj
            else:
                raise Exception("Object name parameter missing. Cannot create object class: %s" % classname)
        else:
            raise Exception("Object class %s not registered in factory. Cannot create object." % classname)

# -------------------------------------------------------------------------------
# global reference kind of a singleton
factory = ModelObjectFactory()