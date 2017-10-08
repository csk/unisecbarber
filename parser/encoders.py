#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''

import json

def clean(d):
    """
    Delete keys with the value ``None`` in a dictionary, recursively.

    This alters the input so you may wish to ``copy`` the dict first.
    """
    # For Python 3, write `list(d.items())`; `d.items()` won’t work
    # For Python 2, write `d.items()`; `d.iteritems()` won’t work
    for key, value in d.items():
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            clean(value)
        elif isinstance(value, list) and len(value) == 0:
            del d[key]
    return d  # For convenience

# thanks to https://stackoverflow.com/a/5165421/220666
class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj,'jsonable'):
            return clean(obj.jsonable())
        else:
            return json.JSONEncoder.default(self, obj)