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
import argparse
import select
import shutil

from config.globals import *

from .config.configuration import getInstanceConfiguration
from .utils.logs import getLogger, setUpLogger
from .encoders import ComplexEncoder
from .parsers import UnisecbarberParser

USER_HOME = os.path.expanduser(CONST_USER_HOME)
UNISECBARBER_BASE = os.path.dirname(os.path.realpath(__file__))

UNISECBARBER_USER_HOME = os.path.expanduser(CONST_UNISECBARBER_HOME_PATH)
UNISECBARBER_PLUGINS_PATH = os.path.join(UNISECBARBER_USER_HOME, CONST_UNISECBARBER_PLUGINS_PATH)
UNISECBARBER_PLUGINS_BASEPATH = os.path.join(UNISECBARBER_BASE, CONST_UNISECBARBER_PLUGINS_REPO_PATH)
UNISECBARBER_USER_CONFIG_XML = os.path.join(UNISECBARBER_USER_HOME, CONST_UNISECBARBER_USER_CFG)
UNISECBARBER_BASE_CONFIG_XML = os.path.join(UNISECBARBER_BASE, CONST_UNISECBARBER_BASE_CFG)
UNISECBARBER_VERSION_FILE = os.path.join(UNISECBARBER_BASE, CONST_VERSION_FILE)

CONF = getInstanceConfiguration()

def setup_folders(folderlist):
    """Checks if a list of folders exists and creates them otherwise.

    """
    for folder in folderlist:
        fp_folder = os.path.join(UNISECBARBER_USER_HOME, folder)
        if not os.path.isdir(fp_folder):
            # getLogger().info("Creating %s" % fp_folder)
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
    
    # getLogger().info("Creating initial folders structure ...")
    # Logger path is created here, so it is available since now
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
                        help="command line to execute")
    parser.add_argument("-v", "--verbose", action="count",
                        help="increase output verbosity")
    parser.add_argument("-o", "--output",
                        help="store to file")
    parser.add_argument("-i", "--input", action="store_true",
                        help="pass input from stdin to cmd")
    parser.add_argument("--init", action="store_true",
                        help="force initializiation")
    parser.add_argument("-d", "--direct", action="store_true",
                        help="pass output direct to plugin")
    parser.add_argument("-p", "--plugin",
                        help="do not guess. select a specific plugin")
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

    show_output=(args.mode == 'cmd')
    if args.direct:
        if not check_stdin():
            parser.print_help()
            sys.exit(0)
        if not args.plugin:
            parser.print_help()
            sys.exit(0)
        direct_output = sys.stdin.read()
        unisecbarber_parser = UnisecbarberParser(plugin=args.plugin)
        result = unisecbarber_parser.parse_output(direct_output)
    else:
        if not args.input and check_stdin():
            cmd_to_run = sys.stdin.read()
        else:
            cmd_to_run = " ".join(args.cmd_input)

        if not cmd_to_run:
            parser.print_help()
            sys.exit(0)

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
