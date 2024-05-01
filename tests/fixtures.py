import pytest

from main import create_app, init_app


@pytest.fixture
def client():
    app = create_app()
    init_app(app, False)
    with app.test_client() as client:
        yield client


test_configuration_params = {
        "walletType": "test",
        "companyName": "test",
        "splashScreenTitle": "test",
        "tagLine": "test",
        "profileName": "test",
        "displayProfile": "displayProfileFalse",
        "displayDeveloperMode": "displayDeveloperModeTrue",
        "displayHelpCenter": "displayHelpCenterTrue",
        "displaySelfSovereignIdentity": "displaySelfSovereignIdentityTrue",
        "displaySecurityAdvancedSettings": "displaySecurityAdvancedSettingsFalse",
        "verifySecurityIssuerWebsiteIdentity": "verifySecurityIssuerWebsiteIdentityFalse",
        "confirmSecurityVerifierAccess": "confirmSecurityVerifierAccessFalse",
        # TODO investigate the non persistence of the False config
        "secureSecurityAuthenticationWithPinCode": "secureSecurityAuthenticationWithPinCodeTrue",
        "tezosSupport": "true",
        "displayManageDecentralizedId": "displayManageDecentralizedIdTrue",
        "scope": "test",
        "statusListCache": "test",
        "cryptoHolderBinding": "test",
        "pushAuthorizationRequest": "test",
        "securityLevel": "test",
        "defaultDid": "test",
        "subjectSyntaxeType": "test",
        "clientAuthentication": "test",
        "client_id": "test",
        "client_secret": "test",
        "oidc4vciDraft": "test",
        "oidc4vpDraft": "test",
        "siopv2Draft": "test",
        "vcFormat": "vc_json",
        "customChatSupportName": "test",
        "customEmail": "test",
        "displayOver13": "displayOver13True",
        "displayOver15": "displayOver15True",
        "displayOver18": "displayOver18True",
        "displayOver18_2": "displayOver18_2True",
        "displayOver21": "displayOver21True",
        "displayOver50": "displayOver50True",
        "displayOver65": "displayOver65True",
        "displayVerifiableId": "displayVerifiableIdTrue",
        "displayVerifiableId2": "displayVerifiableId2True",
        "displayVerifiableIdSdJwt": "displayVerifiableIdSdJwtTrue",
        "displayEmailPass": "displayEmailPassTrue",
        "displayEmailPassJwt": "displayEmailPassJwtTrue",
        "displayPhonePass": "displayPhonePassTrue",
        "displayPhonePassJwt": "displayPhonePassJwtTrue",
        "displayDefi": "displayDefiTrue",
        "displayHumanity": "displayHumanityTrue",
        "displayHumanityJwt": "displayHumanityJwtTrue",
        "isAllowed": "isAllowedFalse",
        "CompanyKey": "test",
        "Companykid": "test",
        "oidv4vcProfile": "OWF"
        }
