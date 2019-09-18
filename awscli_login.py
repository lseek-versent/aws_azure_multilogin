#!/usr/bin/env python3
"""Obtain temporary credentials to one or more AWS accounts using a valid SAML
assertion"""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import base64 
import concurrent.futures as cof
from configparser import ConfigParser
from fnmatch import fnmatch
from functools import partial
import logging
import os
import os.path as osp
import sys
import xml.etree.ElementTree as ET

import boto3


AWS_CFGFILE = osp.join(os.getenv("HOME"), ".aws", "config")
AWS_CREDFILE = osp.join(os.getenv("HOME"), ".aws", "credentials")


class AwsCliLoginPool(object):
    """Use a thread pool to get temp creds for multiple accounts using one SAML
    assertion"""

    def __init__(self, assertion, profile_globs, verbose=False):
        """assertion:
            SAML assertion to provide to the AWS STS API

        profile_globs:
            List of globs to select profiles to log into.

        NOTE: This script assumes that each profile definition in the aws
        config file contains the following definitions:
            - azure_default_role_arn
        and gets the temp credentials FOR THOSE ROLES ONLY. If the default role
        for the profile is not defined then the role is skipped."""
        self.log = self.getLogger(verbose)
        self.assertion = assertion
        self.principal_arns = self.parse_assertion()
        self.config, self.credentials = self.read_cfg(AWS_CFGFILE, AWS_CREDFILE)
        self.profiles = self.select_profiles(profile_globs)

    def read_cfg(self, cfg_file, creds_file):
        config = ConfigParser()
        config.read(cfg_file)
        creds = ConfigParser()
        creds.read(creds_file)
        return config, creds

    def getLogger(self, verbose):
        logFormat = '%(levelname)s:%(funcName)s:%(lineno)d: %(message)s'
        formatter = logging.Formatter(fmt=logFormat)
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(formatter)
        log = logging.getLogger(__name__)
        log.propagate = False
        log.addHandler(handler)
        log.setLevel(logging.DEBUG if verbose else logging.INFO)
        return log

    def select_profiles(self, profile_globs):
        """Select profiles that match the user-provided globs"""
        glob_matchers = [partial(fnmatch, pat=p) for p in profile_globs]
        match_filter = lambda s: any([fn(s.replace('profile ', ''))
                                      for fn in glob_matchers])
        return list(filter(match_filter, self.config.sections()))

    def parse_assertion(self):
        """Parse the SAML assertion to get principal arns"""
        xml = base64.b64decode(self.assertion).decode()
        self.log.debug('xml:%s', xml)
        root = ET.fromstring(xml)
        # Note: element tree seems to capitalize tags and attribute keys
        role_list_name = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
        role_tag = '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
        xpath_expr = ".//{}[@Name='{}']".format(role_tag, role_list_name)
        roles = root.findall(xpath_expr)
        assert len(roles) == 1, \
            "SAML Response error - could not find (unique) set of roles"

        role_principal_map = {}
        for child in roles[0].findall('.*'):
            self.log.debug('child:%s', child.text)
            parts = child.text.split(',')
            # Apparently the principal/role can appear in any order
            role_idx = 0 if 'role' in parts[0] else 1
            principal_idx = 1 - role_idx
            role_arn, principal_arn = parts[role_idx], parts[principal_idx]
            role_principal_map[role_arn] = principal_arn
        return role_principal_map

    def login_profile(self, profile):
        """Log into one profile using the configured default role.
        
        For convenience the "profile" parameter DOES NOT include the
        'profile' string - just the name of the profile"""
        self.log.debug('Logging into profile:%s', profile)
        profile_cfg = self.config[profile]
        role_arn = profile_cfg.get('azure_default_role_arn', None)
        if not role_arn:
            self.log.warning('No default role found for profile:%s', profile)
            return
        duration = int(profile_cfg.get('azure_default_duration_hours', 1)) * 3600
        sts = boto3.client('sts')
        resp = sts.assume_role_with_saml(RoleArn=role_arn,
                                         PrincipalArn=self.principal_arns[role_arn],
                                         SAMLAssertion=self.assertion,
                                         DurationSeconds=duration)
        resp_creds = resp['Credentials']
        profile_creds = {
            'aws_access_key_id': resp_creds['AccessKeyId'],
            'aws_secret_access_key': resp_creds['SecretAccessKey'],
            'aws_session_token': resp_creds['SessionToken'],
            'aws_session_expiration': resp_creds['Expiration'].isoformat()[:-6] + 'Z'
        }
        self.credentials[profile.replace('profile ', '')] = profile_creds
        self.log.debug('Got credentials for profile:%s', profile)

    def parallel_login(self, nthreads=1):
        with cof.ThreadPoolExecutor(max_workers=nthreads) as executor:
            futures = [executor.submit(self.login_profile, p)
                       for p in self.profiles]
            cof.wait(futures)
        self.write_creds()

    def write_creds(self):
        with open(AWS_CREDFILE, "w") as creds_file:
            self.credentials.write(creds_file)


def main(argv=sys.argv):
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description='Log into multiple AWS accounts with a SAML assertion'
    )
    parser.add_argument('-f', '--assertion-file', default='-',
        help='File to read SAML assertion from. Use "-" for stdin')
    parser.add_argument('-n', '--n-threads', default=1, type=int,
        help=('Number of threads to use. Useful when you need to log into '
              'a large number of accounts because the SAML assertion has a '
              'validity of only 5 minutes'))
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Enable verbose debug logs')
    parser.add_argument('profiles', nargs='+',
        help='List of GLOBs (not regexes) to select profiles to log into.')
    args = parser.parse_args(argv[1:])

    infile = open(args.assertion_file) if args.assertion_file != '-' else sys.stdin
    assertion = infile.read()
    infile.close()
    client = AwsCliLoginPool(assertion,
                             set(args.profiles),
                             args.verbose)
    client.parallel_login(args.n_threads)


if __name__ == '__main__':
    main()
