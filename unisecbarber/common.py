#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import hashlib
# from persistence.server.server_io_exceptions import MoreThanOneObjectFoundByID

def get_hash(parts):
    return hashlib.sha1("._.".join(parts)).hexdigest()

# https://stackoverflow.com/a/4256027/220666
def del_none(d):
    """
    Delete keys with the value ``None`` in a dictionary, recursively.

    This alters the input so you may wish to ``copy`` the dict first.
    """
    # For Python 3, write `list(d.items())`; `d.items()` won’t work
    # For Python 2, write `d.items()`; `d.iteritems()` won’t work
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            del_none(value)
    return d  # For convenience


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
        if classname in self._registered_objects:
            if object_name is not None:
                objargs['name'] = object_name
                objargs['_id'] = -1  # they still don't have a server id
                objargs['id'] = -1 # we'll generate it after making sure the objects are okey
                tmpObj = self._registered_objects[classname](objargs)
                tmpObj.set_id(parent_id)
                return tmpObj
            else:
                raise Exception("Object name parameter missing. Cannot create object class: %s" % classname)
        else:
            raise Exception("Object class %s not registered in factory. Cannot create object." % classname)

# -------------------------------------------------------------------------------
# global reference kind of a singleton
factory = ModelObjectFactory()