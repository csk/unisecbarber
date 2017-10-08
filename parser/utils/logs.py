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
from config.globals import CONST_SECTOOLPARSER_HOME_PATH, CONST_SECTOOLPARSER_LOGS_PATH


SECTOOLPARSER_USER_HOME = CONST_SECTOOLPARSER_HOME_PATH
LOG_FILE = os.path.join(
    CONST_SECTOOLPARSER_LOGS_PATH, 'sectoolparser.log')


def setUpLogger(debug=False):
    level = logging.INFO
    if debug:
        level = logging.DEBUG

    logger = logging.getLogger('sectoolparser')
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
    logger.addHandler(fh)


def addHandler(handler):
    logger = logging.getLogger('sectoolparser')
    logger.addHandler(handler)


def getLogger(obj=None):
    """Creates a logger named by a string or an object's class name.
     Allowing logger to additionally accept strings as names
     for non-class loggings.
    """
    if obj is None:
        logger = logging.getLogger(
            'sectoolparser')
    elif type(obj) is str:
        logger = logging.getLogger(
            '%s.%s' % ('sectoolparser', obj))
    else:
        logger = logging.getLogger(
            '%s.%s' % ('sectoolparser', obj.__class__.__name__))
    return logger
