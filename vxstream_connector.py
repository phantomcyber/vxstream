# --
# File: vxstream_connector.py
#
# Copyright (C) 2017 Payload Security UG (haftungsbeschrankt)
#
# --

# Phantom imports

import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

try:
    from phantom.vault import Vault
except:
    import phantom.vault as Vault

from vxstream_consts import *

# Other imports used by this connector
import json
import requests
import uuid
import shutil
import os
from io import BytesIO
import gzip
import time
from datetime import datetime
import urllib
from urlparse import urlparse
from os.path import splitext, basename

from api_classes.api_api_key_data import ApiApiKeyData
from api_classes.api_search import ApiSearch
from api_classes.api_submit_file import ApiSubmitFile
from api_classes.api_submit_url import ApiSubmitUrl
from api_classes.api_summary import ApiSummary
from api_classes.api_result import ApiResult
from api_classes.api_check_state import ApiCheckState


class VxError(Exception):
    pass


class VxStreamConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_DETONATE_URL = 'detonate_url'
    ACTION_ID_DETONATE_FILE = 'detonate_file'
    ACTION_ID_GET_REPORT = 'get_report'
    ACTION_ID_RUN_QUERY = 'run_query'
    ACTION_ID_HUNT_FILE = 'hunt_file'
    ACTION_ID_HUNT_IP = 'hunt_ip'
    ACTION_ID_HUNT_URL = 'hunt_url'
    ACTION_ID_HUNT_DOMAIN = 'hunt_domain'
    ACTION_ID_HUNT_MALWARE_FAMILY = 'hunt_malware_family'
    ACTION_ID_HUNT_SIMILAR = 'hunt_similar'
    ACTION_ID_GET_FILE = 'get_file'
    ACTION_ID_GET_PCAP = 'get_pcap'
    ACTION_ID_GET_FILE_FROM_URL = 'get_file_from_url'
    ACTION_ID_CHECK_STATUS = 'check_status'

    _base_url = ''
    _request_session = None

    def __init__(self):
        super(VxStreamConnector, self).__init__()
        self._api_token = None

    def initialize(self):
        config = self.get_config()
        self._base_url = config[PAYLOAD_SECURITY_WEBSERVICE_BASE_URL]
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        if self._base_url.endswith('vxstream-sandbox.com'):
            self._base_url = self._base_url.replace('vxstream-sandbox.com', 'falcon-sandbox.com')

        if 'https://' not in self._base_url:
            self.save_progress('Warning: Using encrypted connection over https is strongly recommended.')

        self._request_session = requests.Session()

        return phantom.APP_SUCCESS

    def handle_exception(self, exception):
        self.set_status(phantom.APP_ERROR, 'Unexpected error has occurred')

        return self.get_status()

    def _if_request_failed(self, api_object):
        return api_object.get_response_msg_success_nature() is False

    def _get_file_dict(self, param, action_result):
        vault_id = param['vault_id']

        try:
            if hasattr(Vault, 'get_file_path'):
                payload = open(Vault.get_file_path(vault_id), 'rb')
            else:
                payload = open(Vault.get_vault_file(vault_id), 'rb')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'File not found in vault ("{}")'.format(vault_id)), None

        files = {'file': (param['file_name'], payload)}

        return phantom.APP_SUCCESS, files

    def _make_api_call(self, api_object):
        config = self.get_config()
        api_object.call(self._request_session, verify_server=config[PAYLOAD_SECURITY_VERIFY_SERVER_CERT])

    def _make_api_call_with_err_handling(self, api_object, base_err_msg):
        try:
            self._make_api_call(api_object)
        except requests.exceptions.RequestException as exc:
            raise VxError('{} Connection to server failed. Error: \'{}\''.format(base_err_msg, str(exc)))

        if self._if_request_failed(api_object) is True:
            raise VxError('{} {}'.format(base_err_msg, api_object.get_prepared_response_msg()))

        return api_object

    def _build_sample_url(self, url_params):
        sample_url = '{}/sample/{}'.format(self._base_url, url_params['sha256'])
        if 'environment_id' in url_params and url_params['environment_id'] is not None:
            sample_url = '{}?environmentId={}'.format(sample_url, url_params['environment_id'])

        return sample_url

    def _check_status_partial(self, param):
        config = self.get_config()
        api_check_state = ApiCheckState(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        api_check_state.attach_params({'environmentId': param['environment_id'], 'sha256': param['sha256']})

        return self._make_api_call_with_err_handling(api_check_state, 'Getting sample status failed.')

    def _check_status(self, param):
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            api_check_state = self._check_status_partial(param)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        api_response_json = api_check_state.get_response_json()['response']
        api_response_json['sample_url'] = self._build_sample_url(param)
        api_response_json['status'] = api_response_json['state']
        api_response_json['error_msg'] = '' if 'error' not in api_response_json else api_response_json['error']

        action_result.add_data(api_response_json)
        action_result.set_summary(api_response_json)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully get status of sample with sha256: \'{}\' and environment ID: \'{}\''.format(param['sha256'], param['environment_id']))

    def _get_pcap(self, param):
        param.update({'file_type': 'pcap'})
        return self._get_file(param)

    def _get_file(self, param):
        config = self.get_config()
        api_result_object = ApiResult(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        api_result_object.attach_params({'environmentId': param['environment_id'], 'sha256': param['sha256'], 'type': param['file_type']})

        try:
            self._make_api_call_with_err_handling(api_result_object, 'Getting file failed.')
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        data = self._save_file_to_vault(action_result, api_result_object.get_api_response(), param['sha256'] + '#' + param['environment_id'], param['file_type'])
        data['sample_url'] = self._build_sample_url(param)

        action_result.add_data(data)
        action_result.set_summary(data)

        return action_result.get_status()

    def _get_file_from_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        disassembled = urlparse(param['url'])
        filename, file_ext = splitext(basename(disassembled.path))

        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder '/vault/tmp'.", e)

        f_out_name = local_dir + '/online_file_{}_{}{}'.format(str(time.time()).replace('.', ''), filename, file_ext)

        self.save_progress('Fetching data from given url')
        file_resp = urllib.urlopen(param['url'])
        f_out = open(f_out_name, 'wb')
        f_out.write(file_resp.read())
        f_out.close()

        vault_ret_dict = Vault.add_attachment(f_out_name, self.get_container_id(), file_name=os.path.basename(f_out_name))

        data = {}
        if vault_ret_dict['succeeded']:
            data = {
                'vault_id': vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': os.path.basename(f_out_name),
                'file_type': file_ext[1:],
            }

            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        shutil.rmtree(local_dir)

        action_result.add_data(data)
        action_result.set_summary(data)

        return action_result.get_status()

    def _save_file(self, directory, file_content, file_name_suffix, file_type):
        f_out_name = directory + '/VxStream_{}_{}.{}'.format(str(time.time()).replace('.', ''), file_name_suffix, file_type)
        if file_type == 'memory':
            f_out_name += '.zip'

        if file_type in ['xml', 'html', 'bin', 'pcap']:
            f_out = open(f_out_name, 'wb')
            try:
                gzip_file_handle = gzip.GzipFile(fileobj=BytesIO(file_content))
                f_out.write(gzip_file_handle.read())
            except:
                f_out = open(f_out_name, 'wb')
                f_out.write(file_content)
                f_out.close()
            f_out.close()
        else:
            f_out = open(f_out_name, 'wb')
            f_out.write(file_content)
            f_out.close()

        return f_out_name

    def _save_file_to_vault(self, action_result, response, file_name_suffix, file_type):

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder '/vault/tmp'.", e)

        file_path = self._save_file(local_dir, response.content, file_name_suffix, file_type)

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=os.path.basename(file_path))

        data = {}
        if vault_ret_dict['succeeded']:
            data = {
                'vault_id': vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': os.path.basename(file_path),
                'file_type': file_type,
            }

            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        shutil.rmtree(local_dir)

        return data

    def _get_report_partial(self, param):
        config = self.get_config()
        api_summary_object = ApiSummary(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        api_summary_object.attach_params({'environmentId': param['environment_id'], 'hash': param['hash']})

        self._make_api_call_with_err_handling(api_summary_object, 'Getting report failed.')

        api_response_json = api_summary_object.get_response_json()['response']
        api_response_json['sample_url'] = self._build_sample_url({'sha256': api_response_json['sha256'], 'environment_id': api_response_json['environmentId']})
        if 'threatscore' not in api_response_json:
            api_response_json['threatscore'] = ''

        if 'submitname' not in api_response_json:
            api_response_json['submitname'] = ''

        return {'api_object': api_summary_object, 'prepared_json_response': api_response_json}

    def _get_report(self, param):
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            partial_results = self._get_report_partial(param)
            api_response_json = partial_results['prepared_json_response']
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(api_response_json)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully get summary of sample with hash: \'{}\' and environment ID: \'{}\''.format(param['hash'], param['environment_id']))

    def _detonation_partial(self, param, detonation_api_object):
        api_response_json = detonation_api_object.get_response_json()
        sample_params = {
            'sha256': api_response_json['response']['sha256'],
            'environment_id': param['environment_id']
        }
        final_check_status_response = None
        start_time_of_checking = time.time()

        self.save_progress('Successfully submitted chosen element for detonation. Waiting {} seconds to do status checking...'.format(PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS))
        for x in range(0, PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS):
            self.debug_print('detonate_debug_print_queue', 'Starting iteration {} of {}. Sleep time is {}.'.format(x, PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS,
                                                                                                                       PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS))
            time.sleep(PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS)
            api_check_state = self._check_status_partial(sample_params)
            api_response_json = api_check_state.get_response_json()['response']
            final_check_status_response = api_response_json

            if api_response_json['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS:
                self.save_progress('Submitted element is processed. Waiting {} seconds to do status checking...'.format(PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS))
                for y in range(0, PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS):
                    self.debug_print('detonate_debug_print_progress', 'Starting iteration {} of {}. Sleep time is {}.'.format(y, PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS,
                                                                                                                                  PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS))
                    time.sleep(PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS)
                    api_check_state = self._check_status_partial(sample_params)
                    api_response_json = api_check_state.get_response_json()['response']
                    final_check_status_response = api_response_json
                    self.save_progress(
                        PAYLOAD_SECURITY_MSG_CHECKED_STATE.format(api_response_json['state'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), y + 1,
                                                                  PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS,
                                                                  PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS))

                    if api_response_json['state'] in [PAYLOAD_SECURITY_SAMPLE_STATE_SUCCESS, PAYLOAD_SECURITY_SAMPLE_STATE_ERROR]:
                        self.debug_print('detonate_debug_print_progress_result_status',
                                         'Got state \'{}\' from \'{}\' state after \'{}\' seconds of work.'.format(api_response_json['state'], PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS,
                                                                                                                   (time.time() - start_time_of_checking)))
                        break
                else:  # 'else' is ran, when iteration was not broken. When it has happen, break also the outer loop.
                    continue
                break
            elif api_response_json['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_ERROR:
                self.debug_print('detonate_debug_print_queue_result_status',
                                 'Got state \'{}\' from \'{}\' state after \'{}\' seconds of work.'.format(PAYLOAD_SECURITY_SAMPLE_STATE_ERROR, PAYLOAD_SECURITY_SAMPLE_STATE_IN_QUEUE,
                                                                                                           (time.time() - start_time_of_checking)))
                break
            elif api_response_json['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_SUCCESS:
                break
            else:
                self.save_progress(
                    PAYLOAD_SECURITY_MSG_CHECKED_STATE.format(api_response_json['state'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), x + 1, PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS,
                                                              PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS))

        if final_check_status_response['state'] in [PAYLOAD_SECURITY_SAMPLE_STATE_IN_QUEUE, PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS]:
            raise VxError('Action reached the analysis timeout. Last state is \'{}\'. You can still observe the state using \'check status\' action and after successful analysis, retrieve results by \'get report\' action.'.format(final_check_status_response['state']))
        elif final_check_status_response['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_ERROR:
            raise VxError('During the analysis, error has occurred: \'{}\'. For more possible information, please visit sample page({}) and/or Payload Security Knowledge Base.'.format(
                                         final_check_status_response['error'], self._build_sample_url({'sha256': sample_params['sha256'], 'environment_id': sample_params['environment_id']})))
        else:
            self.save_progress(PAYLOAD_SECURITY_MSG_DETONATION_QUERYING_REPORT)
            partial_results = self._get_report_partial({'environment_id': sample_params['environment_id'], 'hash': sample_params['sha256']})
            return partial_results['prepared_json_response']

    def _detonate_url(self, param):
        config = self.get_config()
        api_submit_file_object = ApiSubmitUrl(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_SUBMITTING_FILE)

        action_result = self.add_action_result(ActionResult(dict(param)))
        api_submit_file_object.attach_data({'environmentId': param['environment_id'], 'analyzeurl': param['url']})

        try:
            self._make_api_call_with_err_handling(api_submit_file_object, 'URL submit failed.')
            report_api_json_response = self._detonation_partial(param, api_submit_file_object)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(report_api_json_response)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully submitted URL and retrieved analysis result. Sample sha256: \'{}\' and environment ID: \'{}\''.format(report_api_json_response['sha256'], param['environment_id']))

    def _detonate_file(self, param):
        config = self.get_config()
        api_submit_file_object = ApiSubmitFile(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_SUBMITTING_FILE)

        action_result = self.add_action_result(ActionResult(dict(param)))
        return_value, files = self._get_file_dict(param, action_result)

        if phantom.is_fail(return_value):
            return action_result.get_status()

        api_submit_file_object.attach_files(files)
        api_submit_file_object.attach_data({'environmentId': param['environment_id']})

        try:
            self._make_api_call_with_err_handling(api_submit_file_object, 'File submit failed.')
            report_api_json_response = self._detonation_partial(param, api_submit_file_object)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(report_api_json_response)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully submitted file and retrieved analysis result. Sample sha256: \'{}\' and environment ID: \'{}\''.format(report_api_json_response['sha256'], param['environment_id']))

    def _convert_verdict_name_to_key(self, verdict_name):
        return verdict_name.replace(' ', '_')

    def _hunt_similar(self, param):
        return self._run_query({'query': 'similar-to:' + param['sha256']}, self.add_action_result(ActionResult(dict(param))))

    def _hunt_file(self, param):
        return self._run_query({'query': param['file_identificator']}, self.add_action_result(ActionResult(dict(param))))

    def _hunt_malware_family(self, param):
        return self._run_query({'query': 'tag:' + param['malware_family']}, self.add_action_result(ActionResult(dict(param))))

    def _hunt_domain(self, param):
        return self._run_query({'query': 'domain:' + param['domain']}, self.add_action_result(ActionResult(dict(param))))

    def _hunt_url(self, param):
        return self._run_query({'query': 'url:' + param['url']}, self.add_action_result(ActionResult(dict(param))))

    def _hunt_ip(self, param):
        return self._run_query({'query': 'host:' + param['ip']}, self.add_action_result(ActionResult(dict(param))))

    def _run_query(self, param, action_result=None):
        config = self.get_config()
        api_search_object = ApiSearch(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)

        if action_result is None:
            action_result = self.add_action_result(ActionResult(dict(param)))
        api_search_object.attach_params({'query': param['query']})

        try:
            self._make_api_call_with_err_handling(api_search_object, 'Searched failed.')
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        verdict_summary = dict.fromkeys([self._convert_verdict_name_to_key(verdict_name) for verdict_name in PAYLOAD_SECURITY_SAMPLE_VERDICT_NAMES], 0)
        api_response_json = api_search_object.get_response_json()
        for search_row in api_response_json['response']['result']:
            verdict_summary[self._convert_verdict_name_to_key(search_row['verdict'])] += 1
            environment = None
            threatscore_verbose = None

            if search_row['environmentDescription'] is not None:
                environment = search_row['environmentDescription']

            if search_row['environmentId'] is not None:
                if environment is not None:
                    environment = '{} ({})'.format(environment, search_row['environmentId'])
                else:
                    environment = '{}'.format(search_row['environmentId'])

            if search_row['threatscore'] is not None:
                threatscore_verbose = str(search_row['threatscore']) + '/100'

            search_row['environment'] = environment
            search_row['threatscore_verbose'] = threatscore_verbose

            action_result.add_data(search_row)

        summary = {
            'found': len(api_response_json['response']['result']),
            'found_by_verdict_name': verdict_summary
        }

        action_result.set_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS, 'Found {} matching samples'.format(summary['found']))

    def _test_connectivity(self):
        config = self.get_config()
        api_api_key_data_object = ApiApiKeyData(config[PAYLOAD_SECURITY_API_KEY], config[PAYLOAD_SECURITY_API_SECRET], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        try:
            self._make_api_call(api_api_key_data_object)
        except requests.exceptions.RequestException as exc:
            self.save_progress('Connection to server failed. Error: \'{}\''.format(str(exc)))
            self.set_status(phantom.APP_ERROR, 'Connectivity test failed')
            return self.get_status()
        except ValueError as exc:
            self.save_progress('Connection to server failed. It\'s highly possible that given base URL is invalid. Please re-check it and try again.')
            self.set_status(phantom.APP_ERROR, 'Connectivity test failed')
            return self.get_status()

        if self._if_request_failed(api_api_key_data_object) is True:
            self.save_progress(api_api_key_data_object.get_prepared_response_msg())
            self.set_status(phantom.APP_ERROR, 'Connectivity test failed')
            return self.get_status()

        api_json_response = api_api_key_data_object.get_response_json()

        if api_json_response['response']['auth_level'] < 100:
            self.save_progress('You are using API Key with \'{}\' privileges. Some of actions can not work, as they need at least \'default\' privileges. To obtain proper key, please contact with support@payload-security.com.'.format(api_json_response['response']['auth_level_name']))

        self.save_progress(api_api_key_data_object.get_prepared_response_msg())

        return self.set_status_save_progress(phantom.APP_SUCCESS, 'Connectivity test passed')

    def handle_action(self, param):

        return_value = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', action_id)

        if action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            return_value = self._test_connectivity()
        elif action_id == self.ACTION_ID_DETONATE_FILE:
            return_value = self._detonate_file(param)
        elif action_id == self.ACTION_ID_DETONATE_URL:
            return_value = self._detonate_url(param)
        elif action_id == self.ACTION_ID_GET_REPORT:
            return_value = self._get_report(param)
        elif action_id == self.ACTION_ID_GET_FILE:
            return_value = self._get_file(param)
        elif action_id == self.ACTION_ID_GET_PCAP:
            return_value = self._get_pcap(param)
        elif action_id == self.ACTION_ID_RUN_QUERY:
            return_value = self._run_query(param)
        elif action_id == self.ACTION_ID_HUNT_FILE:
            return_value = self._hunt_file(param)
        elif action_id == self.ACTION_ID_HUNT_IP:
            return_value = self._hunt_ip(param)
        elif action_id == self.ACTION_ID_HUNT_URL:
            return_value = self._hunt_url(param)
        elif action_id == self.ACTION_ID_HUNT_DOMAIN:
            return_value = self._hunt_domain(param)
        elif action_id == self.ACTION_ID_HUNT_MALWARE_FAMILY:
            return_value = self._hunt_malware_family(param)
        elif action_id == self.ACTION_ID_HUNT_SIMILAR:
            return_value = self._hunt_similar(param)
        elif action_id == self.ACTION_ID_CHECK_STATUS:
            return_value = self._check_status(param)
        elif action_id == self.ACTION_ID_GET_FILE_FROM_URL:
            return_value = self._get_file_from_url(param)

        return return_value


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if len(sys.argv) < 2:
        print 'No test json specified as input'
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VxStreamConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
