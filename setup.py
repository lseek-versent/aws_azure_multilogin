#!/usr/bin/env python

from distutils.core import setup
import setuptools


requirements = None
with open('requirements.txt', 'r') as requirement_file:
    all_contents = requirement_file.readlines()
    requirements = [line.strip() for line in all_contents if not line.startswith('#')]


with open('VERSION', 'r') as version_file:
    version = version_file.read().strip()


setup(name='awscli-multilogin',
      version=version,
      description='Log into multiple AWS profiles using one SAML assertion',
      author='David Koo',
      author_email='david.koo@versent.com.au',
      py_modules=['awscli_login'],
      install_requires=requirements,
      entry_points={
          'console_scripts': [
            'aws_multilogin=awscli_login:main',
          ],
      })
