# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''
from __future__ import print_function

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
from .helpers import term_width_line_msg




setUpLogger(False)

CONF = getInstanceConfiguration()
plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(), "plugins"))
plugin_controller = PluginController('PluginController', plugin_manager)

class UnisecbarberParser(object):
    """
    TODO: Doc string.
    """
    def __init__(self, show_output=False):
        self._object_factory = factory
        self._registerObjectTypes()
        self._do_show_output = show_output

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

        if self._do_show_output:
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

        return plugin_controller.parse_command(pid, cmd.returncode, output)


def main():

    parser = argparse.ArgumentParser()
    parser.prog = 'unisecbarber'
    parser.description = """
unisecbarber ("UNIversal SECurity Barber") is an effort to normalize sectools generated data. This tool receives a commandline as an input, parses it to know which tool it is supposed to be, modifies it adding arguments / redirecting output so it can collect the maximum possible data of it. All the collected data is then parsed again and printed out, structured, to the standard output (by default).
"""
    parser.epilog = "___ }:)"

    parser.add_argument("cmd_input", nargs='*', 
                        help="display a square of a given number")
    parser.add_argument("-v", "--verbose", action="count",
                        help="increase output verbosity")
    parser.add_argument("-o", "--output",
                        help="store to file")
    parser.add_argument("-m", "--mode",
                        help="show mode (`cmd`, `json`)")
    args = parser.parse_args()

    show_output=(args.mode == 'cmd')
    if args.verbose >= 1:
        setUpLogger(True)
        
    if select.select([sys.stdin,],[],[],0.0)[0]:
        cmd_to_run = sys.stdin.read()
    else:
        cmd_to_run = " ".join(args.cmd_input)

    if not cmd_to_run:
        parser.print_help()
        sys.exit(0)

    unisecbarber_parser = UnisecbarberParser(show_output=show_output)
    result = unisecbarber_parser.run(cmd_to_run)

    result_output = json.dumps(result, sort_keys=True, indent=4, cls=ComplexEncoder)
    if args.output:
        f = open(args.output, 'w')
        f.write(result_output)
        f.close()
    if args.mode:
        if args.mode == 'cmd':
            pass
        elif args.mode == 'json':
            print(result_output)
        else:
            parser.print_help()
            sys.exit(0)
    else:
        print(result_output)
