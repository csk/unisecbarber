# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''
import re
from setuptools import setup, find_packages

version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open('unisecbarber/unisecbarber.py').read(),
    re.M
    ).group(1)
 

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='unisecbarber',
    version=version,
    description='UNIversal SECurity Barber - Security Tools Parser based on Infobyte Faraday',
    long_description=readme,
    author='Conrad Stein K',
    author_email='conradsteink@gmail.com',
    url='',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    package_data={'unisecbarber.config': ['*.xml']},
    entry_points = {
        "console_scripts": ['unisecbarber = unisecbarber.unisecbarber:main']
    }
)

