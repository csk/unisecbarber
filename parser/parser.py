#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''

import os
import sys
import json
import subprocess
import shlex
from tempfile import mkstemp

from manager import PluginManager
from controller import PluginController
from config.configuration import getInstanceConfiguration
from utils.logs import getLogger, setUpLogger


CONF = getInstanceConfiguration()

setUpLogger(True)
plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(), "plugins"))
plugin_controller = PluginController('PluginController', plugin_manager)

def main():
    
    cmd_input = sys.stdin.read()
    cmd_input = cmd_input.strip(' \t\n\r')

    pwd = os.getcwd()
    pid=1 # maybe not usefull at all
    
    getLogger().info("input: '%s'" % (cmd_input, ))
    plugin_id, mod_cmd = plugin_controller.processCommandInput(pid, cmd_input, pwd)

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


    objs = plugin_controller.parseCommand(pid, cmd.returncode, output)

    getLogger().info("parsed data:\n\n %s" % (json.dumps(objs, indent=4, sort_keys=True)))
    

if __name__ == '__main__':
    main()
