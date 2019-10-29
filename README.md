# AWS CLI Multi-login

A simple script to log in with multiple AWS profiles using a single SAML
assertion. This script would typically be run in conjunction with the
[SAML auth proxy](https://github.com/lseek-versent/saml-authproxy)
server (which retrieves the SAML assertion).

**WARNING**: THIS IS A VERY DANGEROUS TOOL - IT IS EASY TO ACCIDENTALLY
DELETE/DAMAGE STUFF IN THE WRONG ACCOUNT SO USE IT WITH EXTREME CAUTION.

# Typical Usage

Use 2 threads to log into profiles matching 2 `glob` patterns, the accounts
authenticate against a PingID IDP:

    curl -s http://localhost:8080/ping/awsCli | \
    aws_multilogin \
        --client-type ping \
        --n-threads 2
        <glob1> \
        <glob2>

A complete list of the command line options available can be obtained using the
`--help` option:

    awscli_multilogin --help


The script expects each profile definition to contain a
`role_arn` key which defines the ARN of the role to use to
log into the profile. If this key does not exist the profile is skipped
even if it matches a profile pattern specified on the command line.

Additionally, a profile definition can contain a `default_duration_hours` key
that signifies the number of hours requested for the token validity period.
Note: This cannot exceed the maximum period set on AWS.


# Installation

    git clone <this repo>
    pip install .
