import unittest
from tests.fixtures import client, test_configuration_params
from main import set_config
from db import create_organisation, create_user
from repositories.configuration import current_configuration, parse_configuration

def test_should_status_code_ok(client):
    response = client.post('/set_config', data=test_configuration_params)

    assert response.status_code == 302

def test_stores_configuration(client):
    try:
        create_organisation('organization', '{}')
    except:
        None

    with client.session_transaction() as session:
        session["organisation"] = "organization"

    response = client.post('/set_config', data=test_configuration_params)
    configuration = current_configuration("organization")

    assert configuration['generalOptions']['profileId']
    del configuration['generalOptions']['profileId']

    assert configuration['generalOptions']['published']
    del configuration['generalOptions']['published']

    assert configuration.get('generalOptions') == {'walletType': 'test', 'companyName': 'test', 'companyWebsite': 'https://altme.io', 'companyLogo': 'https://talao.co/static/img/icon.png', 'tagLine': 'test', 'splashScreenTitle': 'test', 'profileName': 'test', 'profileVersion': '1.1', 'customerPlan': None, 'organizationStatus': True}
    assert configuration.get('settingsMenu') == {'displayProfile': False, 'displayDeveloperMode': True, 'displayHelpCenter': True, 'displaySelfSovereignIdentity': True}
    assert configuration.get('companySignature') == {'isAllowed': False, 'kid': None, 'CompanyKey': 'test', 'Companykid': 'test'}
    assert configuration.get('walletSecurityOptions') == {'displaySecurityAdvancedSettings': False, 'verifySecurityIssuerWebsiteIdentity': False, 'confirmSecurityVerifierAccess': False, 'secureSecurityAuthenticationWithPinCode': True}
    assert configuration.get('blockchainOptions') == {'tezosSupport': True, 'ethereumSupport': False, 'hederaSupport': False, 'bnbSupport': False, 'fantomSupport': False, 'polygonSupport': False, 'tzproRpcNode': False, 'tzproApiKey': None, 'infuraRpcNode': False, 'infuraApiKey': None}
    assert configuration.get('selfSovereignIdentityOptions') == {'displayManageDecentralizedId': True, 'displaySsiAdvancedSettings': False, 'displayVerifiableDataRegistry': False, 'oidv4vcProfile': 'OWF', 'customOidc4vcProfile': {'vcFormat': 'vc+sd-jwt', 'proofHeader': 'kid', 'proofType': 'jwt', 'statusListCache': True, 'securityLevel': False, 'clientAuthentication': 'client_id', 'credentialManifestSupport': False, 'userPinDigits': '4', 'defaultDid': 'did:jwk:p-256', 'subjectSyntaxeType': 'did', 'cryptoHolderBinding': True, 'scope': False, 'client_id': '', 'client_secret': '', 'oidc4vciDraft': '13', 'oidc4vpDraft': '20', 'siopv2Draft': '12', 'pushAuthorizationRequest': False}}
    assert configuration.get('helpCenterOptions') == {'isChat': False, 'displayChatSupport': False, 'customChatSupport': False, 'customChatSupportName': 'test', 'displayEmailSupport': False, 'customEmailSupport': False, 'customEmail': 'test'}
    assert configuration.get('discoverCardsOptions') == {'displayRewardsCategory': True, 'displayOver18': True, 'displayOver18Jwt': True, 'displayOver13': True, 'displayOver15': True, 'displayOver21': True, 'displayOver50': True, 'displayOver65': True, 'displayEmailPass': True, 'displayEmailPassJwt': True, 'displayPhonePass': True, 'displayPhonePassJwt': True, 'displayAgeRange': False, 'displayGender': False, 'displayVerifiableId': True, 'displayVerifiableIdJwt': True, 'displayVerifiableIdSdJwt': True, 'displayHumanity': True, 'displayHumanityJwt': True, 'displayDefi': True, 'displayChainborn': False, 'displayTezotopia': False, 'displayExternalIssuer': []}

# def test_parse_configuration():
#     assert parse_configuration('organization', test_configuration_params) == {}

if __name__ == '__main__':
    unittest.main()
