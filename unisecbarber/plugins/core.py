#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
'''

from unisecbarber.plugin import PluginBase as PluginBaseExt

# This class was moved to plugins.plugin so we need a way to
# support plugins that are still inheriting from core
PluginBase = PluginBaseExt
