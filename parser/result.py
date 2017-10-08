#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''
import json
from models import (Result,
        Host,
        Interface,
        Service,
        Vuln,
        VulnWeb,
        Credential,
        Note
        )


class ResultBuilder(object):

    def __init__(self):
        self.result = Result()
        self.result.meta = dict(foo='bar')

        self._obj_refs = {}

    def get_result(self):
        return self.result


    def add_item(self, obj):

        print "add_item" + obj.get_id()

        parent_id = None
        if obj.id != None:
            id_arr = obj.id.split('.')
            if len(id_arr) > 1:
                parent_id = id_arr[0]

        parent_obj = None
        if parent_id != None:
            if parent_id in self._obj_refs:
                parent_obj = self._obj_refs[parent_id]

                if obj.class_signature == 'Host':
                    parent_obj.add_host(obj)
                if obj.class_signature == 'Interface':
                    print "Adding iface"
                    parent_obj.add_interface(obj)
                if obj.class_signature == 'Service':
                    parent_obj.add_service(obj)
                if obj.class_signature == 'Vuln':
                    parent_obj.add_vuln(obj)
                if obj.class_signature == 'VulnWeb':
                    parent_obj.add_vuln_web(obj)
                if obj.class_signature == 'Note':
                    parent_obj.add_note(obj)
                if obj.class_signature == 'Cred':
                    parent_obj.add_cred(obj)
        else:
            if obj.class_signature == 'Host':
                print "Adding host"
                self.result.add_host(obj)
        
        self._obj_refs[obj.get_id()] = obj
        return self
