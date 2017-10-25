# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
'''

import pkg_resources
import pip


def check_dependencies(requirements_file='requirements.txt'):
    dependencies_file = open(requirements_file, 'r')

    requirements = list(pkg_resources.parse_requirements(dependencies_file))

    installed = []
    missing = []

    for package in requirements:
        try:
            pkg_resources.working_set.resolve([package])
            installed += [package]
        except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
            missing += [package.key]

    return installed, missing


def install_packages(packages):
    for package in packages:
        pip.main(['install', package, '--user'])
