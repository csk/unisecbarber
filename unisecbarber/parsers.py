# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''
from __future__ import print_function

import os
import sys
import subprocess

from . import models
from .manager import PluginManager
from .controller import PluginController
from .config.configuration import getInstanceConfiguration
from .utils.logs import getLogger
from .common import factory

CONF = getInstanceConfiguration()
class UnisecbarberParser(object):
    """
    TODO: Doc string.
    """
    def __init__(self, show_output=False, stdin_pipe=False, plugin=None):
        self._object_factory = factory
        self._registerObjectTypes()
        self._do_show_output = show_output
        self._do_stdin_pipe = stdin_pipe
        self._plugin = plugin

        CONF = getInstanceConfiguration()
        plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(), "plugins"))
        self._plugin_controller = PluginController('PluginController', plugin_manager)

    def _registerObjectTypes(self):
        """
        Registers in the factory all object types that can be created
        """
        # This could be done in hosts module, but it seems easier to maintain
        # if we have all in one place inside the controller
        self._object_factory.register(models.Host)
        self._object_factory.register(models.Interface)
        self._object_factory.register(models.Service)
        self._object_factory.register(models.Vuln)
        self._object_factory.register(models.VulnWeb)
        self._object_factory.register(models.Note)
        self._object_factory.register(models.Credential)

    def run(self, cmd_input):
        cmd_input = cmd_input.strip(' \t\n\r')

        pwd = os.getcwd()
        
        getLogger().info("input: '%s'" % (cmd_input, ))
        plugin_id, mod_cmd = self._plugin_controller.process_command_input(cmd_input, pwd)

        run_cmd  = cmd_input
        if mod_cmd is not None:
            run_cmd = mod_cmd
        
        final_cmd = "%s 2>&1" % (run_cmd,)
        getLogger().info("running: %s" % (final_cmd,))
        cmd = subprocess.Popen(final_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if self._do_stdin_pipe:
            output, err = cmd.communicate(input=sys.stdin.read())
            if self._do_show_output:
                sys.stdout.write(output)
        elif self._do_show_output:
            output=""
            while True:
                line = cmd.stdout.readline()
                if not line: break
                sys.stdout.write(line)
                output += line
            sys.stdout.flush()
            output2, err = cmd.communicate()
            output += output2
        else:
            output, err = cmd.communicate()

        getLogger().info("output: %s" % (output,))
        getLogger().info("err: %s" % (err,))
        getLogger().info("plugin.id: %s" % (plugin_id,))
        getLogger().info("modified_cmd_string: %s" % (mod_cmd,))

        return self._plugin_controller.parse_command(cmd.returncode, output)

    def parse_output(self, output, cmd_input=None):
        ret_code=0
        if self._plugin:
            plugin = self._plugin_controller.get_plugin_by_id(self._plugin)
        elif cmd_input:
            plugin = self._plugin_controller.get_plugin_by_input(cmd_input)

        if not plugin:
            raise Exception("No plugin found to parse given content!")

        return self._plugin_controller.parse_command(ret_code, output, plugin=plugin)
