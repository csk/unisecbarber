#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''

import json
import models

class HostEncoder(json.JSONEncoder):
    def __init__(self, **kwargs):
        super(HostEncoder, self).__init__(**kwargs)

    def default(self, obj):
        if isinstance(obj, models.Host):
            result = {
                "_type": models.Host.class_signature,
                "name": obj.name
            }
            # ifaces = obj.getAllInterfaces()
            # if len(ifaces) > 0:
            result['interfaces'] = json.JSONEncoder().default((1,2,3))
            return result
        return super(HostEncoder, self).default(obj)


class InterfaceEncoder(json.JSONEncoder):
    def __init__(self, nan_str="null", **kwargs):
        super(HostEncoder, self).__init__(**kwargs)

    def default(self, obj):
        if isinstance(obj, models.Interface):
            return {
                "_type": models.Interface.class_signature,
                "name": obj.name
            }
        return super(HostEncoder, self).default(obj)

