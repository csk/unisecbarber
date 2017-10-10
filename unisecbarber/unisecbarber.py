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
import shutil
from tempfile import mkstemp

from config.globals import *


from . import models
from .manager import PluginManager
from .controller import PluginController
from .config.configuration import getInstanceConfiguration
from .utils.logs import getLogger, setUpLogger
from .common import factory
from .encoders import ComplexEncoder
from .helpers import term_width_line_msg

USER_HOME = os.path.expanduser(CONST_USER_HOME)
UNISECBARBER_BASE = os.path.dirname(os.path.realpath(__file__))

UNISECBARBER_USER_HOME = os.path.expanduser(CONST_UNISECBARBER_HOME_PATH)
UNISECBARBER_PLUGINS_PATH = os.path.join(UNISECBARBER_USER_HOME, CONST_UNISECBARBER_PLUGINS_PATH)
UNISECBARBER_PLUGINS_BASEPATH = os.path.join(UNISECBARBER_BASE, CONST_UNISECBARBER_PLUGINS_REPO_PATH)
UNISECBARBER_USER_CONFIG_XML = os.path.join(UNISECBARBER_USER_HOME, CONST_UNISECBARBER_USER_CFG)
UNISECBARBER_BASE_CONFIG_XML = os.path.join(UNISECBARBER_BASE, CONST_UNISECBARBER_BASE_CFG)
UNISECBARBER_VERSION_FILE = os.path.join(UNISECBARBER_BASE, CONST_VERSION_FILE)

CONF = getInstanceConfiguration()


class UnisecbarberParser(object):
    """
    TODO: Doc string.
    """
    def __init__(self, show_output=False, stdin_pipe=False):
        self._object_factory = factory
        self._registerObjectTypes()
        self._do_show_output = show_output
        self._do_stdin_pipe = stdin_pipe

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
        pid=1 # maybe not usefull at all
        
        getLogger().info("input: '%s'" % (cmd_input, ))
        plugin_id, mod_cmd = self._plugin_controller.process_command_input(pid, cmd_input, pwd)

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

        return self._plugin_controller.parse_command(pid, cmd.returncode, output)

def setup_folders(folderlist):
    """Checks if a list of folders exists and creates them otherwise.

    """
    for folder in folderlist:
        fp_folder = os.path.join(UNISECBARBER_USER_HOME, folder)
        if not os.path.isdir(fp_folder):
            getLogger().info("Creating %s" % fp_folder)
            os.makedirs(fp_folder)

def setup_plugins(force=False):
    """Checks and handles Faraday's plugin status.

    When dev_mode is True, the user enters in development mode and the plugins
    will be replaced with the latest ones.

    Otherwise, it checks if the plugin folders exists or not, and creates it
    with its content.

    TODO: When dependencies are not satisfied ask user if he wants to try and
    run faraday with a inestability warning.

    """
    if os.path.isdir(UNISECBARBER_PLUGINS_PATH):
        if force:
            getLogger().info("Removing and re-creating plugins folder.")
            shutil.rmtree(UNISECBARBER_PLUGINS_PATH)
            shutil.copytree(UNISECBARBER_PLUGINS_BASEPATH, UNISECBARBER_PLUGINS_PATH)
    else:
        getLogger().info("No plugins folder detected. Creating new one.")
        shutil.copytree(UNISECBARBER_PLUGINS_BASEPATH, UNISECBARBER_PLUGINS_PATH)

def setup_xml_config(force=False):
    """Checks user configuration file status.

    If there is no custom config the default one will be copied as a default.
    """

    if os.path.isfile(UNISECBARBER_USER_CONFIG_XML):
        if force:
            getLogger().info("Copying default configuration from project.")
            shutil.copy(UNISECBARBER_BASE_CONFIG_XML, UNISECBARBER_USER_CONFIG_XML)
    else:
        getLogger().info("Copying default configuration from project.")
        if not os.path.exists(os.path.dirname(UNISECBARBER_USER_CONFIG_XML)):
            os.mkdir(os.path.dirname(UNISECBARBER_USER_CONFIG_XML))
        shutil.copy(UNISECBARBER_BASE_CONFIG_XML, UNISECBARBER_USER_CONFIG_XML)


def check_configuration(force=False):
    """Checks if the environment is ready to run Faraday.

    Checks different environment requirements and sets them before starting
    Faraday. This includes checking for plugin folders, libraries,
    and ZSH integration.
    """
    getLogger().info("Creating initial folders structure ...")
    setup_folders(CONST_UNISECBARBER_FOLDER_LIST)
    getLogger().info("Checking configuration ...")
    getLogger().info("Setting up plugins ...")
    setup_plugins(force=force)
    getLogger().info("Setting up user configuration ...")
    setup_xml_config(force=force)

def check_stdin():
    """ Checks it data is being piped in trough stdin """
    return select.select([sys.stdin,],[],[],0.0)[0]


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
    parser.add_argument("-i", "--input", action="store_true",
                        help="pass input from stdin to cmd")
    parser.add_argument("--init", action="store_true",
                        help="force initializiation")
    parser.add_argument("-m", "--mode",
                        help="show mode (`cmd`, `json`)")
    args = parser.parse_args()

    if args.init:
        check_configuration(True)
        print("Copied original configuration and plugins to '%s'" % UNISECBARBER_USER_HOME)
        sys.exit(0)
    else:
        check_configuration()
    CONF.init()

    if args.verbose >= 1:
        setUpLogger(True)
    else:
        setUpLogger(False)


    if not args.input and check_stdin():
        cmd_to_run = sys.stdin.read()
    else:
        cmd_to_run = " ".join(args.cmd_input)

    if not cmd_to_run:
        parser.print_help()
        sys.exit(0)

    show_output=(args.mode == 'cmd')
    unisecbarber_parser = UnisecbarberParser(show_output=show_output, stdin_pipe=args.input)
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
