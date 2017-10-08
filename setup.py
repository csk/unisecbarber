# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='unisecbarber',
    version='0.1.0',
    description='UNIversal SECurity Barber - Security Tools Parser based on Infobyte Faraday',
    long_description=readme,
    author='Conrad Stein K',
    author_email='conradsteink@gmail.com',
    url='',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

