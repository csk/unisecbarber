#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import errno
from cStringIO import StringIO
import multiprocessing
import os
import Queue
import shlex
import time

from utils.logs import getLogger

class PluginController(object):
    """
    TODO: Doc string.
    """
    def __init__(self, id, plugin_manager):
        self.plugin_manager = plugin_manager
        self._plugins = plugin_manager.getPlugins()
        self.id = id
        self.output_path = '.'
        self._active_plugin = None
        self.plugin_set = None
        self.plugin_manager.addController(self, self.id)

    def _find_plugin(self, plugin_id):
        return self._plugins.get(plugin_id, None)

    def _is_command_malformed(self, original_command, modified_command):
        """
        Checks if the command to be executed is safe and it's not in the
        block list defined by the user. Returns False if the modified
        command is ok, True if otherwise.
        """
        block_chars = set(["|", "$", "#"])

        if original_command == modified_command:
            return False

        orig_cmd_args = shlex.split(original_command)

        if not isinstance(modified_command, basestring):
            modified_command = ""
        mod_cmd_args = shlex.split(modified_command)

        block_flag = False
        orig_args_len = len(orig_cmd_args)
        for index in xrange(0, len(mod_cmd_args)):
            if (index < orig_args_len and
                    orig_cmd_args[index] == mod_cmd_args[index]):
                continue

            for char in block_chars:
                if char in mod_cmd_args[index]:
                    block_flag = True
                    break

        return block_flag

    def _get_plugins_by_input(self, cmd, plugin_set):
        for plugin in plugin_set.itervalues():
            if plugin.canParseCommandString(cmd):
                return plugin
        return None

    def getAvailablePlugins(self):
        """
        Return a dictionary with the available plugins.
        Plugin ID's as keys and plugin instences as values
        """
        return self._plugins

    def updatePluginSettings(self, plugin_id, new_settings):

        if plugin_id in self.plugin_set:
            plugin_set[plugin_id].updateSettings(new_settings)
        if plugin_id in self._plugins:
            self._plugins[plugin_id].updateSettings(new_settings)

    def createPluginSet(self):
        self.plugin_set = self.plugin_manager.getPlugins()

    def get_plugin_by_id(self, pid):
        if not self.plugin_set:
            self.createPluginSet()
        if pid in self.plugin_set.keys():
            return self.plugin_set[pid]
        return None

    def process_command_input(self, cmd, pwd):
        """
        This method tries to find a plugin to parse the command sent
        by the terminal (identiefied by the process id).
        """
        if not self.plugin_set:
            self.createPluginSet()

        plugin = self._get_plugins_by_input(cmd, self.plugin_set)

        if plugin:
            modified_cmd_string = plugin.processCommandString("", pwd, cmd)
            if not self._is_command_malformed(cmd, modified_cmd_string):
                cmd_info = {
                        'itime': time.time(),
                        'command': cmd.split()[0],
                        'params': ' '.join(cmd.split()[1:])
                        }
                self._active_plugin = plugin, cmd_info

                return plugin.id, modified_cmd_string
        return None, None

    def parse_command(self, exit_code, term_output, plugin=None):

        if plugin:
            plugin.process_output(term_output)
            return plugin.get_result()
        elif not self._active_plugin:
            return False
        if exit_code != 0:
            self._active_plugin = None
            return False

        plugin, cmd_info = self._active_plugin
        plugin.process_output(term_output)

        cmd_info['duration'] = time.time() - cmd_info['itime']

        self._active_plugin = None
        return plugin.get_result()


    def clearActivePlugins(self):
        self._active_plugin = None
