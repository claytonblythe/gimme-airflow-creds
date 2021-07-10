#!/usr/bin/env python3
"""
Copyright 2016-present Nike, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and* limitations under the License.*
"""
# For enumerating saml roles
# standard imports
import configparser
import json
import os
import re
import sys

# extras
import boto3
from botocore.exceptions import ClientError
from okta.framework.ApiClient import ApiClient
from okta.framework.OktaError import OktaError

# local imports
from . import errors, ui
from .config import Config
from .default import DefaultResolver
from .okta import OktaClient
from .registered_authenticators import RegisteredAuthenticators


class GimmeAIRFLOWCreds(object):
    """
       This is a CLI tool that gets temporary airflow credentials
       from Okta based the available airflow Okta Apps and roles
       assigned to the user. The user is able to select the app
       and role from the CLI or specify them in a config file by
       passing --action-configure to the CLI too.
       gimme_airflow_creds will either write the credentials to stdout
       or ~/.airflow/credentials depending on what was specified when
       --action-configure was ran.

       Usage:
          -h, --help            show this help message and exit
          --username USERNAME, -u USERNAME
                                The username to use when logging into Okta. The
                                username can also be set via the OKTA_USERNAME env
                                variable. If not provided you will be prompted to
                                enter a username.
          --action-configure, -c       If set, will prompt user for configuration parameters
                                and then exit.
          --profile PROFILE, -p PROFILE
                                If set, the specified configuration profile will be
                                used instead of the default.
          --resolve, -r         If set, performs alias resolution.
          --insecure, -k        Allow connections to SSL sites without cert
                                verification.
          --mfa-code MFA_CODE   The MFA verification code to be used with SMS or TOTP
                                authentication methods. If not provided you will be
                                prompted to enter an MFA verification code.
          --remember-device, -m
                                The MFA device will be remembered by Okta service for
                                a limited time, otherwise, you will be prompted for it
                                every time.
          --version             gimme-airflow-creds version

        Config Options:
           okta_org_url = Okta URL
           gimme_creds_server = URL of the gimme-creds-server
           client_id = OAuth Client id for the gimme-creds-server
           okta_auth_server = Server ID for the OAuth authorization server used by gimme-creds-server
           write_airflow_creds = Option to write creds to ~/.airflow/credentials
           cred_profile = Use DEFAULT or Role-based name as the profile in ~/.airflow/credentials
           airflow_appname = (optional) Okta airflow App Name
           airflow_rolename =  (optional) airflow Role ARN. 'ALL' will retrieve all roles, can be a CSV for multiple roles.
           okta_username = (optional) Okta User Name
    """
    resolver = DefaultResolver()
    envvar_list = [
        'AIRFLOW_DEFAULT_DURATION',
        'CLIENT_ID',
        'CRED_PROFILE',
        'GIMME_AIRFLOW_CREDS_CLIENT_ID',
        'GIMME_AIRFLOW_CREDS_CRED_PROFILE',
        'GIMME_AIRFLOW_CREDS_OUTPUT_FORMAT',
        'OKTA_AUTH_SERVER',
        'OKTA_DEVICE_TOKEN',
        'OKTA_MFA_CODE',
        'OKTA_PASSWORD',
        'OKTA_USERNAME',
    ]

    envvar_conf_map = {
        'GIMME_AIRFLOW_CREDS_CLIENT_ID': 'client_id',
        'GIMME_AIRFLOW_CREDS_CRED_PROFILE': 'cred_profile',
        'GIMME_AIRFLOW_CREDS_OUTPUT_FORMAT': 'output_format',
        'OKTA_DEVICE_TOKEN': 'device_token',
    }

    def __init__(self, ui=ui.cli):
        """
        :type ui: ui.UserInterface
        """
        self.ui = ui
        self.FILE_ROOT = self.ui.HOME
        self.AIRFLOW_CONFIG = self.ui.environ.get(
            'AIRFLOW_SHARED_CREDENTIALS_FILE',
            os.path.join(self.FILE_ROOT, '.airflow', 'credentials')
        )
        self._cache = {}

    #  this is modified code from https://github.com/nimbusscale/okta_aws_login
    def _write_airflow_creds(self, profile, access_key, secret_key, token, airflow_config=None):
        """ Writes the airflow STS token into the airflow credential file"""
        # Check to see if the airflow creds path exists, if not create it
        airflow_config = airflow_config or self.AIRFLOW_CONFIG
        creds_dir = os.path.dirname(airflow_config)

        if os.path.exists(creds_dir) is False:
            os.makedirs(creds_dir)

        config = configparser.RawConfigParser()

        # Read in the existing config file if it exists
        if os.path.isfile(airflow_config):
            config.read(airflow_config)

        # Put the credentials into a saml specific section instead of clobbering
        # the default credentials
        if not config.has_section(profile):
            config.add_section(profile)

        config.set(profile, 'airflow_access_key_id', access_key)
        config.set(profile, 'airflow_secret_access_key', secret_key)
        config.set(profile, 'airflow_session_token', token)
        config.set(profile, 'airflow_security_token', token)

        # Write the updated config file
        with open(airflow_config, 'w+') as configfile:
            config.write(configfile)
        # Update file permissions to secure  sensitive credentials file
        os.chmod(airflow_config, 0o600)
        self.ui.result('Written profile {} to {}'.format(profile, airflow_config))

    def write_airflow_creds_from_data(self, data, airflow_config=None):
        if not isinstance(data, dict):
            self.ui.warning('json line is not a dict! ' + repr(data))
            return

        airflow_config = airflow_config or data.get('shared_credentials_file')
        credentials = data.get('credentials', {})
        profile = data.get('profile', {})

        errs = []
        if not isinstance(profile, dict):
            errs.append('profile is not a dict!' + repr(profile))
        else:
            for key in ('name',):
                value = profile.get(key, None)
                if not value:
                    errs.append('{} is not set {} in profile! {}'.format(key, repr(value), str(profile.keys())))

        if not isinstance(credentials, dict):
            errs.append('credentials are not a dict!' + repr(credentials))
        else:
            for key in ('airflow_access_key_id',
                        'airflow_secret_access_key',
                        'airflow_session_token'):
                value = credentials.get(key, None)
                if not value:
                    errs.append(
                        '{} is not set {} in credentials! {}'.format(key, repr(value), str(credentials.keys())))

        if errs:
            for error in errs:
                self.ui.warning(error)
            return

        arn = data.get('role', {}).get('arn', '<no-arn>')
        self.ui.result('Saving {} as {}'.format(arn, profile['name']))
        self._write_airflow_creds(
            profile['name'],
            credentials['airflow_access_key_id'],
            credentials['airflow_secret_access_key'],
            credentials['airflow_session_token'],
            airflow_config=airflow_config,
        )


    @staticmethodx
    def _call_gimme_creds_server(okta_connection, gimme_creds_server_url):
        """ Retrieve the user's airflow accounts from the gimme_creds_server"""
        response = okta_connection.get(gimme_creds_server_url)

        # Throw an error if we didn't get any accounts back
        if not response.json():
            raise errors.GimmeAIRFLOWCredsError("No airflow accounts found.")

        return response.json()x

    @staticmethod
    def _get_airflow_account_info(okta_org_url, okta_api_key, username):
        """ Call the Okta User API and process the results to return
        just the information we need for gimme_airflow_creds"""
        # We need access to the entire JSON response from the Okta APIs, so we need to
        # use the low-level ApiClient instead of UsersClient and AppInstanceClient
        users_client = ApiClient(okta_org_url, okta_api_key, pathname='/api/v1/users')

        # Get User information
        try:
            result = users_client.get_path('/{0}'.format(username))
            user = result.json()
        except OktaError as e:
            if e.error_code == 'E0000007':
                raise errors.GimmeAIRFLOWCredsError("Error: " + username + " was not found!")
            else:
                raise errors.GimmeAIRFLOWCredsError("Error: " + e.error_summary)

        try:
            # Get first page of results
            result = users_client.get_path('/{0}/appLinks'.format(user['id']))
            final_result = result.json()

            # Loop through other pages
            while 'next' in result.links:
                result = users_client.get(result.links['next']['url'])
                final_result = final_result + result.json()
            ui.default.info("done\n")
        except OktaError as e:
            if e.error_code == 'E0000007':
                raise errors.GimmeAIRFLOWCredsError("Error: No applications found for " + username)
            else:
                raise errors.GimmeAIRFLOWCredsError("Error: " + e.error_summary)

        # Loop through the list of apps and filter it down to just the info we need
        app_list = []
        for app in final_result:
            # All airflow connections have the same app name
            if app['appName'] == 'amazon_airflow':
                new_app_entry = {
                    'id': app['id'],
                    'name': app['label'],
                    'links': {
                        'appLink': app['linkUrl'],
                        'appLogo': app['logoUrl']
                    }
                }
                app_list.append(new_app_entry)

        # Throw an error if we didn't get any accounts back
        if not app_list:
            raise errors.GimmeAIRFLOWCredsError("No airflow accounts found.")

        return app_list


    @staticmethod
    def _get_alias_from_friendly_name(friendly_name):
        """ Extracts alias from friendly name string """
        res = None
        matches = re.match(r"Account:\s(?P<alias>.+)\s\(\d{12}\)", friendly_name)
        if matches:
            res = matches.group('alias')
        return res

    def _choose_app(self, airflow_info):
        """ gets a list of available apps and
        ask the user to select the app they want
        to assume a roles for and returns the selection
        """
        if not airflow_info:
            return None

        if len(airflow_info) == 1:
            return airflow_info[0]  # auto select when only 1 choice

        app_strs = []
        for i, app in enumerate(airflow_info):
            app_strs.append('[{}] {}'.format(i, app["name"]))

        if app_strs:
            self.ui.message("Pick an app:")
            # print out the apps and let the user select
            for app in app_strs:
                self.ui.message(app)
        else:
            return None

        selection = self._get_user_int_selection(0, len(airflow_info) - 1)

        if selection is None:
            raise errors.GimmeAIRFLOWCredsError("You made an invalid selection")

        return airflow_info[int(selection)]

    def _get_selected_app(self, airflow_appname, airflow_info):
        """ select the application from the config file if it exists in the
        results from Okta.  If not, present the user with a menu."""

        if airflow_appname:
            for _, app in enumerate(airflow_info):
                if app["name"] == airflow_appname:
                    return app
                elif app["name"] == "fakelabel":
                    # auto select this app
                    return app
            self.ui.error("ERROR: airflow account [{}] not found!".format(airflow_appname))

        # Present the user with a list of apps to choose from
        return self._choose_app(airflow_info)

    def _get_user_int_selection(self, min_int, max_int, max_retries=5):
        selection = None
        for _ in range(0, max_retries):
            try:
                selection = int(self.ui.input("Selection: "))
                break
            except ValueError:
                self.ui.warning('Invalid selection, must be an integer value.')

        if selection is None:
            return None

        # make sure the choice is valid
        if selection < min_int or selection > max_int:
            return None

        return selection

    def _get_selected_roles(self, requested_roles, airflow_roles):
        """ select the role from the config file if it exists in the
        results from Okta.  If not, present the user with a menu. """
        # 'all' is a special case - skip processing
        if requested_roles == 'all':
            return set(role.role for role in airflow_roles)
        # check to see if a role is in the config and look for it in the results from Okta
        if requested_roles:
            ret = set()
            if isinstance(requested_roles, str):
                requested_roles = requested_roles.split(',')

            for role_name in requested_roles:
                role_name = role_name.strip()
                if not role_name:
                    continue

                is_regexp = len(role_name) > 2 and role_name[0] == role_name[-1] == '/'
                pattern = re.compile(role_name[1:-1])
                for airflow_role in airflow_roles:
                    if airflow_role.role == role_name or (is_regexp and pattern.search(airflow_role.role)):
                        ret.add(airflow_role.role)

            if ret:
                return ret
            self.ui.error("ERROR: airflow roles [{}] not found!".format(', '.join(requested_roles)))

        # Present the user with a list of roles to choose from
        return self._choose_roles(airflow_roles)

    def _choose_roles(self, roles):
        """ gets a list of available roles and
        asks the user to select the role they want to assume
        """
        if not roles:
            return set()

        # Check if only one role exists and return that role
        if len(roles) == 1:
            single_role = roles[0].role
            self.ui.info("Detected single role: {}".format(single_role))
            return {single_role}

        # Gather the roles available to the user.
        role_strs = self.resolver._display_role(roles)

        if role_strs:
            self.ui.message("Pick a role:")
            for role in role_strs:
                self.ui.message(role)
        else:
            return set()

        selections = self._get_user_int_selections_many(0, len(roles) - 1)

        if not selections:
            raise errors.GimmeAIRFLOWCredsError("You made an invalid selection")

        return {roles[int(selection)].role for selection in selections}

    def _get_user_int_selections_many(self, min_int, max_int, max_retries=5):
        for _ in range(max_retries):
            selections = set()
            error = False

            for value in self.ui.input('Selections (comma separated): ').split(','):
                value = value.strip()

                if not value:
                    continue

                try:
                    selection = int(value)
                except ValueError:
                    self.ui.warning('Invalid selection {}, must be an integer value.'.format(repr(value)))
                    error = True
                    continue

                if min_int <= selection <= max_int:
                    selections.add(value)
                else:
                    self.ui.warning(
                        'Selection {} out of range <{}, {}>'.format(repr(selection), min_int, max_int))

            if error:
                continue

            if selections:
                return selections

        return set()

    def run(self):
        try:
            self._run()
        except errors.GimmeAIRFLOWCredsExitBase as exc:
            exc.handle()

    def generate_config(self):
        """ generates a new configuration and populates
        various config caches
        """
        self._cache['config'] = config = Config(gac_ui=self.ui)
        config.get_args()
        self._cache['conf_dict'] = config.get_config_dict()

        for value in self.envvar_list:
            if self.ui.environ.get(value):
                key = self.envvar_conf_map.get(value, value).lower()
                self.conf_dict[key] = self.ui.environ.get(value)

        # airflow Default session duration ....
        if self.conf_dict.get('airflow_default_duration'):
            self.config.airflow_default_duration = int(self.conf_dict['airflow_default_duration'])
        else:
            self.config.airflow_default_duration = 3600

        self.resolver = self.get_resolver()
        return config

    @property
    def config(self):
        if 'config' in self._cache:
            return self._cache['config']
        config = self.generate_config()
        return config

    @property
    def conf_dict(self):
        """
        :rtype: dict
        """
        # noinspection PyUnusedLocal
        config = self.config
        return self._cache['conf_dict']

    @property
    def output_format(self):
        return self.conf_dict.setdefault('output_format', self.config.output_format)

    @property
    def okta_org_url(self):
        ret = self.conf_dict.get('okta_org_url')
        if not ret:
            raise errors.GimmeAIRFLOWCredsError('No Okta organization URL in configuration.  Try running --config again.')
        return ret

    @property
    def gimme_creds_server(self):
        ret = self.conf_dict.get('gimme_creds_server')
        if not ret:
            raise errors.GimmeAIRFLOWCredsError('No Gimme-Creds server URL in configuration.  Try running --config again.')
        return ret

    @property
    def okta(self):
        if 'okta' in self._cache:
            return self._cache['okta']

        okta = self._cache['okta'] = OktaClient(
            self.ui,
            self.okta_org_url,
            self.config.verify_ssl_certs,
            self.device_token,
        )

        if self.config.username is not None:
            okta.set_username(self.config.username)
        elif self.conf_dict.get('okta_username'):
            okta.set_username(self.conf_dict['okta_username'])

        if self.conf_dict.get('okta_password'):
            okta.set_password(self.conf_dict['okta_password'])

        if self.conf_dict.get('preferred_mfa_type'):
            okta.set_preferred_mfa_type(self.conf_dict['preferred_mfa_type'])

        if self.config.mfa_code is not None:
            okta.set_mfa_code(self.config.mfa_code)
        elif self.conf_dict.get('okta_mfa_code'):
            okta.set_mfa_code(self.conf_dict.get('okta_mfa_code'))

        okta.set_remember_device(self.config.remember_device
                                 or self.conf_dict.get('remember_device', False))
        return okta

    @property
    def device_token(self):
        if self.config.action_register_device is True:
            self.conf_dict['device_token'] = None

        return self.conf_dict.get('device_token')

    def set_auth_session(self, auth_session):
        self._cache['auth_session'] = auth_session

    @property
    def auth_session(self):
        if 'auth_session' in self._cache:
            return self._cache['auth_session']
        auth_result = self.okta.auth_session()
        self.set_auth_session(auth_result)
        return auth_result

    @property
    def airflow_results(self):
        if 'airflow_results' in self._cache:
            return self._cache['airflow_results']
        # Call the Okta APIs and process data locally
        if self.gimme_creds_server == 'internal':
            # Okta API key is required when calling Okta APIs internally
            if self.config.api_key is None:
                raise errors.GimmeAIRFLOWCredsError('OKTA_API_KEY environment variable not found!')
            auth_result = self.auth_session
            airflow_results = self._get_airflow_account_info(self.okta_org_url, self.config.api_key,
                                                     auth_result['username'])

        elif self.gimme_creds_server == 'appurl':
            self.auth_session
            # bypass lambda & API call
            # Apps url is required when calling with appurl
            if self.conf_dict.get('app_url'):
                self.config.app_url = self.conf_dict['app_url']
            if self.config.app_url is None:
                raise errors.GimmeAIRFLOWCredsError('app_url is not defined in your config!')

            # build app list
            airflow_results = []
            new_app_entry = {
                'id': 'fakeid',  # not used anyway
                'name': 'fakelabel',  # not used anyway
                'links': {'appLink': self.config.app_url}
            }
            airflow_results.append(new_app_entry)

        self._cache['airflow_results'] = airflow_results
        return airflow_results

    @property
    def aws_app(self):
        if 'aws_app' in self._cache:
            return self._cache['aws_app']
        self._cache['airflow_app'] = aws_app = self._get_selected_app(self.conf_dict.get('aws_appname'), self.aws_results)
        return aws_app

    @property
    def saml_data(self):
        if 'saml_data' in self._cache:
            return self._cache['saml_data']
        self._cache['saml_data'] = saml_data = self.okta.get_saml_response(self.aws_app['links']['appLink'])
        return saml_data

    @property
    def aws_roles(self):
        if 'aws_roles' in self._cache:
            return self._cache['aws_roles']

        self._cache['aws_roles'] = roles = self.resolver._enumerate_saml_roles(
            self.saml_data['SAMLResponse'],
            self.saml_data['TargetUrl'],
        )
        return roles

    @property
    def aws_selected_roles(self):
        if 'aws_selected_roles' in self._cache:
            return self._cache['aws_selected_roles']
        selected_roles = self._get_selected_roles(self.requested_roles, self.aws_roles)
        self._cache['aws_selected_roles'] = ret = [
            role
            for role in self.aws_roles
            if role.role in selected_roles
        ]
        return ret

    @property
    def requested_roles(self):
        if 'requested_roles' in self._cache:
            return self._cache['requested_roles']
        self._cache['requested_roles'] = requested_roles = self.config.roles or self.conf_dict.get('aws_rolename', '')
        return requested_roles

    @property
    def aws_partition(self):
        if 'aws_partition' in self._cache:
            return self._cache['aws_partition']
        self._cache['aws_partition'] = aws_partition = self._get_partition_from_saml_acs(self.saml_data['TargetUrl'])
        return aws_partition

    def prepare_data(self, role, generate_credentials=False):
        aws_creds = {}
        if generate_credentials:
            try:
                aws_creds = self._get_sts_creds(
                    self.aws_partition,
                    self.saml_data['SAMLResponse'],
                    role.idp,
                    role.role,
                    self.config.aws_default_duration,
                )
            except ClientError as ex:
                if 'requested DurationSeconds exceeds the MaxSessionDuration' in ex.response['Error']['Message']:
                    self.ui.warning(
                        "The requested session duration was too long for this role.  Falling back to 1 hour.")
                    aws_creds = self._get_sts_creds(
                        self.aws_partition,
                        self.saml_data['SAMLResponse'],
                        role.idp,
                        role.role,
                        3600,
                    )
                else:
                    self.ui.error('Failed to generate credentials for {} due to {}'.format(role.role, ex))

        naming_data = self._parse_role_arn(role.role)
        # set the profile name
        # Note if there are multiple roles
        # it will be overwritten multiple times and last role wins.
        cred_profile = self.conf_dict['cred_profile']
        resolve_alias = self.conf_dict['resolve_aws_alias']
        include_path = self.conf_dict.get('include_path')
        profile_name = self.get_profile_name(cred_profile, include_path, naming_data, resolve_alias, role)

        return {
            'shared_credentials_file': self.AIRFLOW_CONFIG,
            'profile': {
                'name': profile_name,
                'derived_name': naming_data['role'],
                'config_name': self.conf_dict.get('cred_profile', ''),
            },
            'role': {
                'arn': role.role,
                'name': role.role,
                'friendly_name': role.friendly_role_name,
                'friendly_account_name': role.friendly_account_name,
            },
            'credentials': {
                'aws_access_key_id': aws_creds.get('AccessKeyId', ''),
                'aws_secret_access_key': aws_creds.get('SecretAccessKey', ''),
                'aws_session_token': aws_creds.get('SessionToken', ''),
                'aws_security_token': aws_creds.get('SessionToken', ''),
                'expiration': aws_creds.get('Expiration').isoformat(),
            } if bool(aws_creds) else {}
        }

    def get_profile_name(self, cred_profile, include_path, naming_data, resolve_alias, role):
        if cred_profile.lower() == 'default':
            profile_name = 'default'
        elif cred_profile.lower() == 'role':
            profile_name = naming_data['role']
        elif cred_profile.lower() == 'acc-role':
            account = naming_data['account']
            role_name = naming_data['role']
            path = naming_data['path']
            if resolve_alias == 'True':
                account_alias = self._get_alias_from_friendly_name(role.friendly_account_name)
                if account_alias:
                    account = account_alias
            if include_path == 'True':
                role_name = ''.join([path, role_name])
            profile_name = '-'.join([account,
                                     role_name])
        else:
            profile_name = cred_profile
        return profile_name

    def iter_selected_aws_credentials(self):
        results = []
        for role in self.aws_selected_roles:
            data = self.prepare_data(role, generate_credentials=True)
            if not data:
                continue
            results.append(data)
            yield data

        self._cache['selected_aws_credentials'] = results

    @property
    def selected_aws_credentials(self):
        if 'selected_aws_credentials' in self._cache:
            return self._cache['selected_aws_credentials']
        self._cache['selected_aws_credentials'] = ret = list(self.iter_selected_aws_credentials())
        return ret

    def _run(self):
        """ Pulling it all together to make the CLI """
        self.handle_action_configure()
        self.handle_action_register_device()
        self.handle_action_list_profiles()
        self.handle_action_store_json_creds()
        self.handle_action_list_roles()
        self.handle_setup_fido_authenticator()
  
        # for each data item, if we have an override on output, prioritize that
        # if we do not, prioritize writing credentials to file if that is in our
        # configuration. If we are not writing to a credentials file, use whatever
        # is in the output format field (default to exports)
        for data in self.iter_selected_aws_credentials():
            if self.config.action_output_format:
                self.write_result_action(self.config.action_output_format, data)
                continue

            write_aws_creds = str(self.conf_dict['write_aws_creds']) == 'True'
            # check if write_aws_creds is true if so
            # get the profile name and write out the file
            if write_aws_creds:
                self.write_aws_creds_from_data(data)
                continue

            self.write_result_action(self.conf_dict["output_format"], data)

        self.config.clean_up()

    def write_result_action(self, action, data):
        if action == "json":
            self.ui.result(json.dumps(data))
            return
        else:
            # Defaults to `export` format
            self.ui.result("export AIRFLOW_ROLE_ARN=" + data['role']['arn'])
            self.ui.result("export AIRFLOW_ACCESS_KEY_ID=" +
                           data['credentials']['aws_access_key_id'])
            self.ui.result("export AIRFLOW_SECRET_ACCESS_KEY=" +
                           data['credentials']['aws_secret_access_key'])
            self.ui.result("export AIRFLOW_SESSION_TOKEN=" +
                           data['credentials']['aws_session_token'])
            self.ui.result("export AIRFLOW_SECURITY_TOKEN=" +
                           data['credentials']['aws_security_token'])


    def handle_action_configure(self):
        # Create/Update config when configure arg set
        if not self.config.action_configure:
            return
        self.config.update_config_file()
        raise errors.GimmeAIRFLOWCredsExitSuccess()

    def handle_action_list_profiles(self):
        if not self.config.action_list_profiles:
            return
        if os.path.isfile(self.config.OKTA_CONFIG):
            with open(self.config.OKTA_CONFIG, 'r') as okta_config:
                raise errors.GimmeAIRFLOWCredsExitSuccess(result=okta_config.read())
        raise errors.GimmeAIRFLOWCredsExitError('{} is not a file'.format(self.config.OKTA_CONFIG))

    def handle_action_store_json_creds(self, stream=None):
        if not self.config.action_store_json_creds:
            return

        stream = stream or sys.stdin
        for line in stream:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                self.ui.warning('error parsing json line {}'.format(repr(line)))
                continue
            self.write_aws_creds_from_data(data)
        raise errors.GimmeAIRFLOWCredsExitSuccess()

    def handle_action_register_device(self):
        # Capture the Device Token and write it to the config file
        if self.device_token is None or self.config.action_register_device is True:
            if not self.config.action_register_device:
                self.ui.notify('\n*** No device token found in configuration file, it will be created.')
                self.ui.notify('*** You may be prompted for MFA more than once for this run.\n')

            auth_result = self.auth_session
            base_config = self.config.get_config_dict(include_inherits = False)
            base_config['device_token'] = auth_result['device_token']
            self.config.write_config_file(base_config)
            self.okta.device_token = base_config['device_token']

            self.ui.notify('\nDevice token saved!\n')

            if self.config.action_register_device is True:
                raise errors.GimmeAIRFLOWCredsExitSuccess()

    def handle_action_list_roles(self):
        if self.config.action_list_roles:
            raise errors.GimmeAIRFLOWCredsExitSuccess(result='\n'.join(map(str, self.aws_roles)))

    def handle_setup_fido_authenticator(self):
        if self.config.action_setup_fido_authenticator:
            # Registers a new fido authenticator to Okta, to be used later as an MFA device
            self.ui.notify('\n*** Registering a new fido authenticator in Okta.')
            self.ui.notify('\n*** Note that webauthn authenticators must be allowed for this operation to succeed.')
            self.ui.notify('*** You may be prompted for MFA more than once for this run.\n')

            # noinspection PyStatementEffect
            self.auth_session

            self.okta.set_preferred_mfa_type(None)
            credential_id, user = self.okta.setup_fido_authenticator()

            registered_authenticators = RegisteredAuthenticators(self.ui)
            registered_authenticators.add_authenticator(credential_id, user)
            raise errors.GimmeAIRFLOWCredsExitSuccess()
