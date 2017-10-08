# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''

__version__ = "0.1.0"

import os
import sys
import json
import subprocess
import shlex
import argparse
import select
from tempfile import mkstemp

from . import models
from .manager import PluginManager
from .controller import PluginController
from .config.configuration import getInstanceConfiguration
from .utils.logs import getLogger, setUpLogger
from .common import factory
from .encoders import ComplexEncoder


setUpLogger(False)

CONF = getInstanceConfiguration()
plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(), "plugins"))
plugin_controller = PluginController('PluginController', plugin_manager)

class UnisecbarberParser(object):
    """
    TODO: Doc string.
    """
    def __init__(self):
        self._object_factory = factory
        self._registerObjectTypes()

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
        pid=1 # maybe not usefull at all
        
        getLogger().info("input: '%s'" % (cmd_input, ))
        plugin_id, mod_cmd = plugin_controller.process_command_input(pid, cmd_input, pwd)

        run_cmd  = cmd_input
        if mod_cmd is not None:
            run_cmd = mod_cmd
        
        f, tmp_file = mkstemp()
        os.close(f)

        final_cmd = "%s 2>&1 | tee -a %s" % (run_cmd, tmp_file)
        getLogger().info("running: %s" % (final_cmd,))
        cmd = subprocess.Popen(final_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = cmd.communicate()

        getLogger().info("output: %s" % (output,))
        getLogger().info("err: %s" % (err,))
        getLogger().info("plugin.id: %s" % (plugin_id,))
        getLogger().info("modified_cmd_string: %s" % (mod_cmd,))

        return plugin_controller.parse_command(pid, cmd.returncode, output)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("cmd_input", nargs='*', 
                        help="display a square of a given number")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="increase output verbosity")
    args = parser.parse_args()
    if args.verbose:
        setUpLogger(True)
    
    if select.select([sys.stdin,],[],[],0.0)[0]:
        cmd_to_run = sys.stdin.read()
    else:
        cmd_to_run = " ".join(args.cmd_input)

    if not cmd_to_run:
        parser.print_help()
        sys.exit(0)

    parser = UnisecbarberParser()
    result = parser.run(cmd_to_run)
    print json.dumps(result, sort_keys=True, indent=4, cls=ComplexEncoder)