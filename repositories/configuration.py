import json
from glom import assign
import base64
import uuid
from datetime import datetime
import re
from db import read_config_from_organisation, read_plan
from repositories.constants import database_mapping

default_configuration = json.load(open('./wallet-provider-configuration.json', 'r'))


def current_configuration(organization_name):
    return read_config_from_organisation(organization_name)

def set_configuration(organization_name, params):
    configuration = parse_configuration(organization_name, params)
    default = default_configuration.copy()
    return merge_dicts(default, configuration)

def parse_configuration(organization_name, params):
    configuration = base_configuration(organization_name)

    for key, value in params.items():
        field_configuration = database_mapping.get(key, None)
        if not field_configuration: continue

        match field_configuration['type']:
            case 'string':
                assign(configuration, field_configuration['target'], params[key])
            case 'boolean':
                assign(configuration, field_configuration['target'], bool(re.search(key + 'True', params[key])))
            case 'securityLevel':
                assign(configuration, field_configuration['target'], params[key] == 'strict')
            case 'presence':
                assign(configuration, field_configuration['target'], True)

    return configuration

def base_configuration(organization_name):
    return {
            'generalOptions': {
                'published': datetime.today().strftime('%Y-%m-%d'),
                'customerPlan': read_plan(organization_name),
                'profileId': base64.b64encode(str(uuid.uuid1()).encode()).decode().replace("=", "")[:10]},
            'settingsMenu': {},
            'walletSecurityOptions': {},
            'blockchainOptions': {
                'tezosSupport': False,
                'ethereumSupport': False,
                'hederaSupport': False,
                'bnbSupport': False,
                'fantomSupport': False,
                'polygonSupport': False},
            'helpCenterOptions': {
                'displayChatSupport': False,
                'customChatSupport': False,
                'displayEmailSupport': False,
                'customEmailSupport': False},
            'discoverCardsOptions': {},
            'companySignature': {},
            'selfSovereignIdentityOptions': {
                'displayVerifiableDataRegistry': False,
                'displaySsiAdvancedSettings': False,
                'customOidc4vcProfile': {}}}


def merge_dicts(dict1, dict2):
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        return dict2
    for k in dict2:
        if k in dict1:
            dict1[k] = merge_dicts(dict1[k], dict2[k])
        else:
            dict1[k] = dict2[k]
    return dict1
