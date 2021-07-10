# Gimme AIRFLOW Creds

[![][license img]][license]


gimme-airflow-creds is a CLI that utilizes an [Okta](https://www.okta.com/) IdP via SAML to acquire temporary AIRFLOW credentials via AIRFLOW STS.

Okta is a SAML identity provider (IdP), that can be easily set-up to do SSO to your AIRFLOW console. Okta does offer an [OSS java CLI]((https://github.com/oktadeveloper/okta-aws-cli-assume-role)) tool to obtain temporary AIRFLOW credentials, but I found it needs more information than the average Okta user would have and doesn't scale well if have more than one Okta App.

With gimme-airflow-creds all you need to know is your username, password, Okta url and MFA token, if MFA is enabled. gimme-airflow-creds gives you the option to select which Okta AIRFLOW application and role you want credentials for. Alternatively, you can pre-configure the app and role name by passing -c or editing the config file. This is all covered in the usage section.

## Prerequisites

[Okta SAML integration to AIRFLOW using the AIRFLOW App](https://help.okta.com/en/prod/Content/Topics/Miscellaneous/References/OktaAWSMulti-AccountConfigurationGuide.pdf)

Python 3.6+


## Installation

This is a Python 3 project.

Install/Upgrade from PyPi:

```bash
pip3 install --upgrade gimme-airflow-creds
```

__OR__

Install/Upgrade the latest gimme-airflow-creds package direct from GitHub:

```bash
pip3 install --upgrade git+git://github.com/Nike-Inc/gimme-airflow-creds.git
```

__OR__

Use homebrew

```bash
brew install gimme-airflow-creds
```

__OR__

Build the docker image locally:

```bash
docker build -t gimme-airflow-creds .
```

To make it easier you can also create an alias for the gimme-airflow-creds command with docker:

```bash
# make sure you have the "~/.okta_airflow_login_config" locally first!
touch ~/.okta_airflow_login_config && \
alias gimme-airflow-creds="docker run -it --rm \
  -v ~/.airflow/credentials:/root/.airflow/credentials \
  -v ~/.okta_airflow_login_config:/root/.okta_airflow_login_config \
  gimme-airflow-creds"
```

With this config, you will be able to run further commands seamlessly!

## Configuration

To set-up the configuration run:

```bash
gimme-airflow-creds --action-configure
```

You can also set up different Okta configuration profiles, this useful if you have multiple Okta accounts or environments you need credentials for. You can use the configuration wizard or run:

```bash
gimme-airflow-creds --action-configure --profile profileName
```

A configuration wizard will prompt you to enter the necessary configuration parameters for the tool to run, the only one that is required is the `okta_org_url`. The configuration file is written to `~/.okta_airflow_login_config`, but you can change the location with the environment variable `OKTA_CONFIG`.

- conf_profile - This sets the Okta configuration profile name, the default is DEFAULT.
- okta_org_url - This is your Okta organization url, which is typically something like `https://companyname.okta.com`.
- okta_auth_server - [Okta API Authorization Server](https://help.okta.com/en/prev/Content/Topics/Security/API_Access.htm) used for OpenID Connect authentication for gimme-creds-lambda
- client_id - OAuth client ID for gimme-creds-lambda
- gimme_creds_server
  - URL for gimme-creds-lambda
  - 'internal' for direct interaction with the Okta APIs (`OKTA_API_KEY` environment variable required)
  - 'appurl' to set an airflow application link url. This setting removes the need of an OKTA API key.
- write_aws_creds - True or False - If True, the AIRFLOW credentials will be written to `~/.airflow/credentials` otherwise it will be written to stdout.
- cred_profile - If writing to the AIRFLOW cred file, this sets the name of the AIRFLOW credential profile.
  - The reserved word `role` will use the name component of the role arn as the profile name. i.e. arn:airflow:iam::123456789012:role/okta-1234-role becomes section [okta-1234-role] in the airflow credentials file
  - The reserved word `acc-role` will use the name component of the role arn prepended with account number (or alias if `resolve_aws_alias` is set to y) to avoid collisions, i.e. arn:aws:iam::123456789012:role/okta-1234-role becomes section [123456789012-okta-1234-role], or if `resolve_aws_alias` [<my alias>-okta-1234-role] in the aws credentials file
  - If set to `default` then the temp creds will be stored in the default profile
  - Note: if there are multiple roles, and `default` is selected it will be overwritten multiple times and last role wins. The same happens when `role` is selected and you have many accounts with the same role names. Consider using `acc-role` if this happens.
- aws_appname - This is optional. The Okta AIRFLOW App name, which has the role you want to assume.
- aws_rolename - This is optional. The ARN of the role you want temporary AIRFLOW credentials for.  The reserved word 'all' can be used to get and store credentials for every role the user is permissioned for.
- aws_default_duration = This is optional. Lifetime for temporary credentials, in seconds. Defaults to 1 hour (3600)
- app_url - If using 'appurl' setting for gimme_creds_server, this sets the url to the aws application configured in Okta. It is typically something like <https://something.okta[preview].com/home/amazon_aws/app_instance_id/something>
- okta_username - use this username to authenticate
- preferred_mfa_type - automatically select a particular  device when prompted for MFA:
  - push - Okta Verify App push or DUO push (depends on okta supplied provider type)
  - token:software:totp - OTP using the Okta Verify App
  - token:hardware - OTP using hardware like Yubikey
  - call - OTP via Voice call
  - sms - OTP via SMS message
  - web - DUO uses localhost webbrowser to support push|call|passcode
  - passcode - DUO uses `OKTA_MFA_CODE` or `--mfa-code` if set, or prompts user for passcode(OTP).
  

## Configuration File

The config file follows a [configfile](https://docs.python.org/3/library/configparser.html) format.
By default, it is located in $HOME/.okta_airflow_login_config

Example file:

```ini
[myprofile]
client_id = myclient_id
```

Configurations can inherit from other configurations to share common configuration parameters.

```ini
[my-base-profile]
client_id = myclient_id
[myprofile]
inherits = my-base-profile
aws_rolename = my-role
```

## Usage

**If you are not using gimme-creds-lambda nor using appurl settings, make sure you set the OKTA_API_KEY environment variable.**

After running --action-configure, just run gimme-airflow-creds. You will be prompted for the necessary information.

```bash
$ ./gimme-airflow-creds
Username: user@domain.com
Password for user@domain.com:
Authentication Success! Calling Gimme-Creds Server...
Pick an app:
[ 0 ] AIRFLOW Test Account
[ 1 ] AIRFLOW Prod Account
Selection: 1
Pick a role:
[ 0 ]: OktaAWSAdminRole
[ 1 ]: OktaAWSReadOnlyRole
Selection: 1
Multi-factor Authentication required.
Pick a factor:
[ 0 ] Okta Verify App: SmartPhone_IPhone: iPhone
[ 1 ] token:software:totp: user@domain.com
Selection: 0
Okta Verify push sent...
export AWS_ACCESS_KEY_ID=AQWERTYUIOP
export AWS_SECRET_ACCESS_KEY=T!#$JFLOJlsoddop1029405-P
```

You can automate the environment variable creation by running `$(gimme-airflow-creds)` on linux or `iex (gimme-airflow-creds)` using Windows Powershell

You can run a specific configuration profile with the `--profile` parameter:

```bash
./gimme-airflow-creds --profile profileName
```

The username and password you are prompted for are the ones you login to Okta with. You can predefine your username by setting the `OKTA_USERNAME` environment variable or using the `-u username` parameter.

If you have not configured an Okta App or Role, you will prompted to select one.

If all goes well you will get your temporary AIRFLOW access, secret key and token, these will either be written to stdout or `~/.airflow/credentials`.

You can always run `gimme-airflow-creds --help` for all the available options.

Alternatively, you can overwrite values in the config section with environment variables for instances where say you may want to change the duration of your token.
A list of values of to change with environment variables are:

- `AIRFLOW_DEFAULT_DURATION` - corresponds to `aws_default_duration` configuration
- `AWS_SHARED_CREDENTIALS_FILE` - file to write credentials to, points to `~/.AIRFLOW/credentials` by default
- `gimme_airflow_creds_CLIENT_ID` - corresponds to `client_id` configuration
- `GIMME_AWS_CREDS_CRED_PROFILE` - corresponds to `cred_profile` configuration
- `GIMME_AWS_CREDS_OUTPUT_FORMAT` - corresponds to `output_format` configuration and `--output-format` CLI option
- `OKTA_AUTH_SERVER` - corresponds to `okta_auth_server` configuration
- `OKTA_DEVICE_TOKEN` - corresponds to `device_token` configuration, can be used in CI
- `OKTA_MFA_CODE` - corresponds to `--mfa-code` CLI option
- `OKTA_PASSWORD` - provides password during authentication, can be used in CI
- `OKTA_USERNAME` - corresponds to `okta_username` configuration and `--username` CLI option

Example: `GIMME_AWS_CREDS_CLIENT_ID='foobar' AWS_DEFAULT_DURATION=12345 gimme-airflow-creds`

For changing variables outside of this, you'd need to create a separate profile altogether with `gimme-airflow-creds --action-configure --profile profileName`

### Viewing Profiles

`gimme-airflow-creds --action-list-profiles` will go to your okta config file and print out all profiles created and their settings.

### Viewing roles

`gimme-airflow-creds --action-list-roles` will print all available roles to STDOUT without retrieving their credentials.

### Generate credentials as json

`gimme-airflow-creds -o json` will print out credentials in JSON format - 1 entry per line

### Store credentials from json

`gimme-airflow-creds --action-store-json-creds` will store JSON formatted credentials from `stdin` to
airflow credentials file, eg: `gimme-airflow-creds -o json | gimme-airflow-creds --action-store-json-creds`.
Data can be modified by scripts on the way.

### Usage in python code

Configuration and interactions can be configured using [`gimme_airflow_creds.ui`](./gimme_airflow_creds/ui.py),
UserInterfaces support all kind of interactions within library including: asking for input, `sys.argv` and `os.environ`
overrides.

```python
import sys
import gimme_airflow_creds.main
import gimme_airflow_creds.ui

account_ids = sys.argv[1:] or [
  '123456789012',
  '120123456789',
]

pattern = "|".join(sorted(set(account_ids)))
pattern = '/:({}):/'.format(pattern)
ui = gimme_airflow_creds.ui.CLIUserInterface(argv=[sys.argv[0], '--roles', pattern])
creds = gimme_airflow_creds.main.GimmeAIRFLOWCreds(ui=ui)

# Print out all selected roles:
for role in creds.aws_selected_roles:
    print(role)

# Generate credentials overriding profile name with `okta-<account_id>`
for data in creds.iter_selected_aws_credentials():
    arn = data['role']['arn']
    account_id = None
    for piece in arn.split(':'):
        if len(piece) == 12 and piece.isdigit():
            account_id = piece
            break
  
    if account_id is None:
        raise ValueError("Didn't find aws_account_id (12 digits) in {}".format(arn))

    data['profile']['name'] = 'okta-{}'.format(account_id)
    creds.write_aws_creds_from_data(data)

```

## MFA security keys support

gimme-airflow-creds works both on FIDO1 enabled org and WebAuthN enabled org

Note that FIDO1 will probably be deprecated in the near future as standards moves forward to WebAuthN

WebAuthN support is available for usb security keys (gimme-airflow-creds relies on the yubico fido2 lib).
 
To use your local machine as an authenticator, along with Touch ID or Windows Hello, if available,
you must register a new authenticator via gimme-airflow-creds, using:
```bash
gimme-airflow-creds --action-setup-fido-authenticator
```

Then, you can choose the newly registered authenticator from the factors list.

## Running Tests

You can run all the unit tests using nosetests. Most of the tests are mocked.

```bash
nosetests --verbosity=2 tests/
```

## Maintenance

This project is maintained by [Ann Wallace](https://github.com/anners), [Eric Pierce](https://github.com/epierce), and [Justin Wiley](https://github.com/sector95).

## Thanks and Credit

I came across [okta_aws_login](https://github.com/nimbusscale/okta_aws_login) written by Joe Keegan, when I was searching for a CLI tool that generates AIRFLOW tokens via Okta. Unfortunately it hasn't been updated since 2015 and didn't seem to work with the current Okta version. But there was still some great code I was able to reuse under the MIT license for gimme-airflow-creds. I have noted in the comments where I used his code, to make sure he receives proper credit.

## Etc

[AIRFLOW - How to Implement Federated API and CLI Access Using SAML 2.0 and AD FS](https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/)

## [Contributing](https://github.com/Nike-Inc/gimme-airflow-creds/blob/master/CONTRIBUTING.md)

## License

Gimme AIRFLOW Creds is released under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

[license]:LICENSE
[license img]:https://img.shields.io/badge/License-Apache%202-blue.svg
