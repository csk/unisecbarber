#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import logging
import logging.handlers
import os
from unisecbarber.config.globals import CONST_UNISECBARBER_HOME_PATH, CONST_UNISECBARBER_LOGS_PATH


UNISECBARBER_USER_HOME = os.path.expanduser(CONST_UNISECBARBER_HOME_PATH)
LOG_FILE = os.path.join(
    UNISECBARBER_USER_HOME, CONST_UNISECBARBER_LOGS_PATH, 'unisecbarber.log')


def setUpLogger(debug=False):
    level = logging.INFO
    if debug:
        level = logging.DEBUG

    logger = logging.getLogger('unisecbarber')
    logger.propagate = False
    logger.setLevel(level)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # ch = logging.StreamHandler()
    # ch.setFormatter(formatter)
    # logger.addHandler(ch)

    # File logger
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    fh.setFormatter(formatter)
    logger.handlers = [] # empty handlers to avoid repeated logs when calling multiple times
    logger.addHandler(fh)


def addHandler(handler):
    logger = logging.getLogger('unisecbarber')
    logger.addHandler(handler)


def getLogger(obj=None):
    """Creates a logger named by a string or an object's class name.
     Allowing logger to additionally accept strings as names
     for non-class loggings.
    """
    if obj is None:
        logger = logging.getLogger(
            'unisecbarber')
    elif type(obj) is str:
        logger = logging.getLogger(
            '%s.%s' % ('unisecbarber', obj))
    else:
        logger = logging.getLogger(
            '%s.%s' % ('unisecbarber', obj.__class__.__name__))
    return logger
