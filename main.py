from flask import Flask, render_template, request, jsonify, redirect, session, send_file
import flask
import json
import redis
import os
import environment
import logging
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
import base64
import db
from hashlib import sha256
import random
import string
import message
import wallet_provider
import uuid
from datetime import datetime, timedelta
import base64
from werkzeug.utils import secure_filename
from PIL import Image
from io import BytesIO
import requests
from flask_mobility import Mobility
from flask_qrcode import QRcode


VERSION = "1.0.0"


logging.basicConfig(level=logging.INFO)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'achille'
mode = environment.currentMode(myenv)

app = Flask(__name__)
app.secret_key = json.load(open("keys.json", "r"))["appSecretKey"]
app.config['UPLOAD_FOLDER'] = 'logos'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
app.config.update(
    # your application redirect uri. Must not be used in your code
    OIDC_REDIRECT_URI=mode.server+"/redirect",
    # your application secret code for session, random
    SECRET_KEY=json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis'  # Redis server side session
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
sess = Session()
sess.init_app(app)
Mobility(app)
qrcode = QRcode(app)


"""
Init OpenID Connect client PYOIDC with the 3 bridge parameters :  client_id, client_secret and issuer URL
"""

client_metadata = ClientMetadata(
    client_id='hvxitrgzbc',
    client_secret=json.load(open("keys.json", "r"))["client_secret"],
    # post_logout_redirect_uris=['http://127.0.0.1:4000/logout']
    # your post logout uri (optional)
)
provider_config = ProviderConfiguration(issuer='https://talao.co/sandbox/verifier/app',
                                        client_metadata=client_metadata)
auth = OIDCAuthentication({'default': provider_config}, app)

red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def generate_random_string(length):
    characters = string.ascii_uppercase  # + string.digits + string.ascii_lowercase
    return ''.join(random.choice(characters) for _ in range(length))


def generate_random_code(length):
    characters = string.digits  # + string.ascii_lowercase +string.ascii_uppercase
    return ''.join(random.choice(characters) for _ in range(length))


def generate_random_filename(length):
    characters = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return ''.join(random.choice(characters) for _ in range(length))


def get_payload_from_token(token):
    """
    For verifier
    check the signature and return None if failed
    """
    payload = token.split('.')[1]
    # solve the padding issue of the base64 python lib
    payload += "=" * ((4 - len(payload) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def init_app(app, red):
    app.add_url_rule('/',  view_func=landing,
                     methods=['GET'])
    app.add_url_rule('/login',  view_func=login,
                     methods=['GET'])
    app.add_url_rule('/login_password',  view_func=login_password,
                     methods=['POST'])
    app.add_url_rule('/dashboard',  view_func=dashboard,
                     methods=['GET'])
    app.add_url_rule('/setup',  view_func=setup,
                     methods=['GET'])
    app.add_url_rule('/set_config', view_func=set_config, methods=['POST'])
    app.add_url_rule('/add_user', view_func=add_user, methods=['POST'])
    app.add_url_rule('/add_user_guest', view_func=add_user_guest, methods=['POST'])
    app.add_url_rule('/logout', view_func=logout, methods=['POST'])
    app.add_url_rule('/dashboard_talao',
                     view_func=dashboard_talao, methods=['GET'])
    app.add_url_rule('/add_organisation',
                     view_func=add_organisation, methods=['POST'])
    app.add_url_rule('/delete_user',
                     view_func=delete_user, methods=['POST'])
    app.add_url_rule('/delete_organisation',
                     view_func=delete_organisation, methods=['POST'])
    app.add_url_rule('/update_password_admin',
                     view_func=update_password_admin, methods=['POST'])
    app.add_url_rule('/update_password_user',
                     view_func=update_password_user, methods=['POST'])
    app.add_url_rule('/change_plan',
                     view_func=change_plan, methods=['POST'])
    app.add_url_rule('/alert_new_config',
                     view_func=alert_new_config, methods=['POST'])
    app.add_url_rule('/alert_users',
                     view_func=alert_users, methods=['POST'])
    app.add_url_rule('/version',
                     view_func=version, methods=['GET'])
    app.add_url_rule('/change_status',
                     view_func=change_status, methods=['POST'])
    app.add_url_rule('/wallet/status/<wallet_instance_key_thumbprint>',
                     view_func=status_wallet, methods=['GET'])
    app.add_url_rule('/disable_wallet',
                     view_func=disable_wallet, methods=['GET'])
    app.add_url_rule('/disable_wallet_get_code',
                     view_func=disable_wallet_get_code, methods=['POST'])
    app.add_url_rule('/disable_wallet_validate_code',
                     view_func=disable_wallet_validate_code, methods=['POST'])
    app.add_url_rule('/disable_wallet_set_inactive',
                     view_func=disable_wallet_set_inactive, methods=['POST'])
    app.add_url_rule('/update_status_organisation',
                     view_func=update_status_organisation, methods=['POST'])
    app.add_url_rule('/send_message',
                     view_func=send_message, methods=['POST'])
    app.add_url_rule('/add_issuer_db',
                     view_func=add_issuer_db, methods=['POST'])
    app.add_url_rule('/modify_issuer_db',
                     view_func=modify_issuer_db, methods=['POST'])
    app.add_url_rule('/remove_issuer_db',
                     view_func=remove_issuer_db, methods=['POST'])
    app.add_url_rule('/change_issuer_config',
                     view_func=change_issuer_config, methods=['POST'])
    app.add_url_rule('/get_issuer_infos/<id>',
                     view_func=get_issuer_infos, methods=['GET'])
    return


@app.errorhandler(500)
def error_500(e):
    """
    For testing purpose
    Send an email if problems
    """
    if mode.server in ['https://talao.co/']:
        email = 'contact@talao.io'
        message.email('Error 500 wallet provider',
                      email, str(e))
    return redirect(mode.server + '/')


def version():
    return VERSION


@app.route('/logo/<organisation>', methods=['GET'])
def serve_static(organisation: str):
    filename = secure_filename(organisation)+".png"
    try:
        return send_file('./logos/' + filename, download_name=filename)
    except FileNotFoundError:
        return jsonify("not found"), 404


def status_wallet(wallet_instance_key_thumbprint):
    return json.dumps(db.read_status_from_thumbprint(wallet_instance_key_thumbprint))


def disable_wallet():
    return render_template("disable_wallet.html")


def disable_wallet_get_code():

    session["code"] = generate_random_code(4)
    session["email"] = request.get_json().get("email")
    message.messageHTML("Your altme code", request.get_json().get("email"),
                        'code_auth_en', {'code': str(session["code"])})
    return "ok"


def disable_wallet_validate_code():
    if not session.get("code") or not request.get_json().get("code"):
        return "Bad request", 400
    if request.get_json().get("code") == session.get("code"):
        session["disabler"] = True
        return "ok"
    return "Unauthorized", 401


def disable_wallet_set_inactive():
    if session["disabler"]:
        db.update_status_user(session.get("email"), "inactive")
        return "ok"
    return "Unauthorized", 401


def landing():
    if request.MOBILE:
        return render_template("mobile.html")
    else:
        return redirect('/login')


@auth.oidc_auth('default')
def login():
    if request.MOBILE:
        return render_template("mobile.html")
    user_session = UserSession(flask.session)
    if isinstance(user_session.userinfo["vp_token_payload"]["verifiableCredential"], list):
        logging.warning("bad presentation")
        session["organisation"] = None
        session["configured"] = None
        user_session.clear()
        session.clear()
        return redirect("/")
    email = user_session.userinfo["vp_token_payload"]["verifiableCredential"]["credentialSubject"]["email"]
    if not db.read_organisation(email):
        session["organisation"] = None
        session["configured"] = None
        user_session.clear()
        session.clear()
        return render_template("wrong_email.html", email=email)
    if session.get("organisation"):
        if session.get("organisation") == "Talao":
            return redirect('/dashboard_talao')
        return redirect('/dashboard')
    session["email"] = email
    return (render_template("login.html", email=session.get("email")))


def login_password():
    password = request.get_json().get("password")
    verif = db.verify_password_admin(session.get("email"), password)
    if not verif:
        return "Not found", 404
    organisation = db.read_organisation(session.get("email"))
    configured = db.read_configured(organisation)
    if not organisation:
        return "Not found", 404
    elif organisation == "Talao":
        session["organisation"] = organisation
        return {"organisation": "Talao"}, 200
    else:
        session["organisation"] = organisation
        session["configured"] = configured
        return {"organisation": organisation, "configured": configured}, 200


def setup():
    if request.MOBILE:
        return render_template("mobile.html")
    if not session.get("organisation") or session.get("organisation") == "Talao":
        return redirect('/')
    organisation = session["organisation"]
    if db.read_configured(organisation) == 0:
        config = json.load(open('./wallet-provider-configuration.json', 'r'))
    else:
        config = db.read_config_from_organisation(session.get("organisation"))
    issuers = db.read_issuers(organisation)
    if not issuers:
        issuers = []
    else:
        issuers = issuers
    issuers_availables = db.read_issuers_availables(organisation, issuers)
    return render_template("setup.html", config=config, version=VERSION, issuers_availables=issuers_availables)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower(
           ) in app.config['ALLOWED_EXTENSIONS']


def set_config():
    if not session.get("organisation"):
        return redirect('/')
    wallet_provider_configuration = json.load(
        open('./wallet-provider-configuration.json', 'r'))
    wallet_provider_configuration["generalOptions"]["walletType"] = request.form.to_dict()[
        "walletType"]
    wallet_provider_configuration["generalOptions"]["companyName"] = request.form.to_dict()[
        "companyName"]

    wallet_provider_configuration["generalOptions"]["splashScreenTitle"] = request.form.to_dict()[
        "splashScreenTitle"]
    wallet_provider_configuration["generalOptions"]["tagLine"] = request.form.to_dict()[
        "tagLine"]
    wallet_provider_configuration["generalOptions"]["published"] = datetime.today(
    ).strftime('%Y-%m-%d')
    # time.time()
    profileId = base64.b64encode(
        str(uuid.uuid1()).encode()).decode().replace("=", "")[:10]
    wallet_provider_configuration["generalOptions"]["profileId"] = profileId
    wallet_provider_configuration["generalOptions"]["profileName"] = request.form.to_dict()[
        "profileName"]

    wallet_provider_configuration["generalOptions"]["customerPlan"] = db.read_plan(
        session["organisation"])

    if request.form.to_dict()["displayProfile"] == "displayProfileFalse":
        wallet_provider_configuration["settingsMenu"]["displayProfile"] = False
    else:
        wallet_provider_configuration["settingsMenu"]["displayProfile"] = True

    if request.form.to_dict()["displayDeveloperMode"] == "displayDeveloperModeFalse":
        wallet_provider_configuration["settingsMenu"]["displayDeveloperMode"] = False
    else:
        wallet_provider_configuration["settingsMenu"]["displayDeveloperMode"] = True

    if request.form.to_dict()["displayHelpCenter"] == "displayHelpCenterFalse":
        wallet_provider_configuration["settingsMenu"]["displayHelpCenter"] = False
    else:
        wallet_provider_configuration["settingsMenu"]["displayHelpCenter"] = True

    if request.form.to_dict()["displaySelfSovereignIdentity"] == "displaySelfSovereignIdentityFalse":
        wallet_provider_configuration["settingsMenu"]["displaySelfSovereignIdentity"] = False
    else:
        wallet_provider_configuration["settingsMenu"]["displaySelfSovereignIdentity"] = True

    if request.form.to_dict()["displaySecurityAdvancedSettings"] == "displaySecurityAdvancedSettingsFalse":
        wallet_provider_configuration["walletSecurityOptions"]["displaySecurityAdvancedSettings"] = False
    else:
        wallet_provider_configuration["walletSecurityOptions"]["displaySecurityAdvancedSettings"] = True
    if request.form.to_dict()["verifySecurityIssuerWebsiteIdentity"] == "verifySecurityIssuerWebsiteIdentityFalse":
        wallet_provider_configuration["walletSecurityOptions"]["verifySecurityIssuerWebsiteIdentity"] = False
    else:
        wallet_provider_configuration["walletSecurityOptions"]["verifySecurityIssuerWebsiteIdentity"] = True
    if request.form.to_dict()["confirmSecurityVerifierAccess"] == "confirmSecurityVerifierAccessFalse":
        wallet_provider_configuration["walletSecurityOptions"]["confirmSecurityVerifierAccess"] = False
    else:
        wallet_provider_configuration["walletSecurityOptions"]["confirmSecurityVerifierAccess"] = True
    if request.form.to_dict()["secureSecurityAuthenticationWithPinCode"] == "secureSecurityAuthenticationWithPinCodeFalse":
        wallet_provider_configuration["walletSecurityOptions"]["secureSecurityAuthenticationWithPinCode"] = False
    else:
        wallet_provider_configuration["walletSecurityOptions"]["secureSecurityAuthenticationWithPinCode"] = True

    if request.form.to_dict().get("tezosSupport"):
        wallet_provider_configuration["blockchainOptions"]["tezosSupport"] = True
    else:
        wallet_provider_configuration["blockchainOptions"]["tezosSupport"] = False
    if request.form.to_dict().get("ethereumSupport"):
        wallet_provider_configuration["blockchainOptions"]["ethereumSupport"] = True
    else:
        wallet_provider_configuration["blockchainOptions"]["ethereumSupport"] = False
    if request.form.to_dict().get("hederaSupport"):
        wallet_provider_configuration["blockchainOptions"]["hederaSupport"] = True
    else:
        wallet_provider_configuration["blockchainOptions"]["hederaSupport"] = False
    if request.form.to_dict().get("bnbSupport"):
        wallet_provider_configuration["blockchainOptions"]["bnbSupport"] = True
    else:
        wallet_provider_configuration["blockchainOptions"]["bnbSupport"] = False
    if request.form.to_dict().get("fantomSupport"):
        wallet_provider_configuration["blockchainOptions"]["fantomSupport"] = True
    else:
        wallet_provider_configuration["blockchainOptions"]["fantomSupport"] = False
    if request.form.to_dict().get("polygonSupport"):
        wallet_provider_configuration["blockchainOptions"]["polygonSupport"] = True
    else:
        wallet_provider_configuration["blockchainOptions"]["polygonSupport"] = False

    if request.form.to_dict()["displayManageDecentralizedId"] == "displayManageDecentralizedIdFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["displayManageDecentralizedId"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["displayManageDecentralizedId"] = True
    wallet_provider_configuration["selfSovereignIdentityOptions"]["displayVerifiableDataRegistry"] = False
    wallet_provider_configuration["selfSovereignIdentityOptions"]["displaySsiAdvancedSettings"] = False
    """if request.form.to_dict()["displaySsiAdvancedSettings"] == "displaySsiAdvancedSettingsFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["displaySsiAdvancedSettings"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["displaySsiAdvancedSettings"] = True
    

    if request.form.to_dict()["displayVerifiableDataRegistry"] == "displayVerifiableDataRegistryFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["displayVerifiableDataRegistry"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["displayVerifiableDataRegistry"] = True"""

    if request.form.to_dict()["scope"] == "scopeFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["scope"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["scope"] = True
    
    if request.form.to_dict()["cryptoHolderBinding"] == "cryptoHolderBindingFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["cryptoHolderBinding"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["cryptoHolderBinding"] = True

    if request.form.to_dict()["credentialManifestSupport"] == "credentialManifestSupportFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"][
            "customOidc4vcProfile"]["credentialManifestSupport"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"][
            "customOidc4vcProfile"]["credentialManifestSupport"] = True

    if request.form.to_dict()["pushAuthorizationRequest"] == "pushAuthorizationRequestFalse":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["pushAuthorizationRequest"] = False
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["pushAuthorizationRequest"] = True

    if request.form.to_dict().get("displayChatSupport") == "displayChatSupportTrue":
        wallet_provider_configuration["helpCenterOptions"]["displayChatSupport"] = True
    else:
        wallet_provider_configuration["helpCenterOptions"]["displayChatSupport"] = False
    if request.form.to_dict().get("customChatSupport") == "customChatSupportTrue":
        wallet_provider_configuration["helpCenterOptions"]["customChatSupport"] = True
    else:
        wallet_provider_configuration["helpCenterOptions"]["customChatSupport"] = False
    if request.form.to_dict().get("displayEmailSupport") == "displayEmailSupportTrue":
        wallet_provider_configuration["helpCenterOptions"]["displayEmailSupport"] = True
    else:
        wallet_provider_configuration["helpCenterOptions"]["displayEmailSupport"] = False
    if request.form.to_dict().get("customEmailSupport") == "customEmailSupportTrue":
        wallet_provider_configuration["helpCenterOptions"]["customEmailSupport"] = True
    else:
        wallet_provider_configuration["helpCenterOptions"]["customEmailSupport"] = False
    # wallet_provider_configuration["selfSovereignIdentityOptions"]["oidv4vcProfile"] = request.form.to_dict()["oidv4vcProfile"]
    if request.form.to_dict()["securityLevel"] == "strict":
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["securityLevel"] = True
    else:
        wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["securityLevel"] = False
    # wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["userPinDigits"] = request.form.to_dict()[
    #     "userPinDigits"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["defaultDid"] = request.form.to_dict()[
        "defaultDid"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["subjectSyntaxeType"] = request.form.to_dict()[
        "subjectSyntaxeType"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["clientAuthentication"] = request.form.to_dict()[
        "clientAuthentication"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["client_id"] = request.form.to_dict()[
        "client_id"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["client_secret"] = request.form.to_dict()[
        "client_secret"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["oidc4vciDraft"] = request.form.to_dict()[
        "oidc4vciDraft"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["oidc4vpDraft"] = request.form.to_dict()[
        "oidc4vpDraft"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["siopv2Draft"] = request.form.to_dict()[
        "siopv2Draft"]
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["vcFormat"] = request.form.to_dict().get(
        "vcFormat","ldp_vc")
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["proofType"] = request.form.to_dict().get(
        "proofType","jwt")
    wallet_provider_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["proofHeader"] = request.form.to_dict().get(
        "proofHeader","kid")
    wallet_provider_configuration["helpCenterOptions"]["customChatSupportName"] = request.form.to_dict()[
        "customChatSupportName"]
    wallet_provider_configuration["helpCenterOptions"]["customEmail"] = request.form.to_dict()[
        "customEmail"]
    print("resultat","1")
    print(request.form.to_dict().get("displayExternalIssuer"))
    if request.form.to_dict()["displayOver13"] == "displayOver13False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver13"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver13"] = True

    if request.form.to_dict()["displayOver15"] == "displayOver15False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver15"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver15"] = True

    if request.form.to_dict()["displayOver18"] == "displayOver18False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver18"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver18"] = True

    if request.form.to_dict()["displayOver18_2"] == "displayOver18_2False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver18Jwt"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver18Jwt"] = True
        
    if request.form.to_dict()["displayOver21"] == "displayOver21False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver21"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver21"] = True

    if request.form.to_dict()["displayOver50"] == "displayOver50False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver50"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver50"] = True

    if request.form.to_dict()["displayOver65"] == "displayOver65False":
        wallet_provider_configuration["discoverCardsOptions"]["displayOver65"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayOver65"] = True

    if request.form.to_dict()["displayVerifiableId"] == "displayVerifiableIdFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayVerifiableId"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayVerifiableId"] = True
    
    if request.form.to_dict()["displayVerifiableId2"] == "displayVerifiableId2False":
        wallet_provider_configuration["discoverCardsOptions"]["displayVerifiableIdJwt"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayVerifiableIdJwt"] = True

    if request.form.to_dict()["displayVerifiableIdSdJwt"] == "displayVerifiableIdSdJwtFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayVerifiableIdSdJwt"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayVerifiableIdSdJwt"] = True

    if request.form.to_dict()["displayEmailPass"] == "displayEmailPassFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayEmailPass"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayEmailPass"] = True
    
    if request.form.to_dict()["displayEmailPassJwt"] == "displayEmailPassJwtFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayEmailPassJwt"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayEmailPassJwt"] = True

    if request.form.to_dict()["displayPhonePass"] == "displayPhonePassFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayPhonePass"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayPhonePass"] = True

    if request.form.to_dict()["displayPhonePassJwt"] == "displayPhonePassJwtFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayPhonePassJwt"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayPhonePassJwt"] = True

    if request.form.to_dict()["displayDefi"] == "displayDefiFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayDefi"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayDefi"] = True

    if request.form.to_dict()["displayHumanity"] == "displayHumanityFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayHumanity"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayHumanity"] = True

    if request.form.to_dict()["displayHumanityJwt"] == "displayHumanityJwtFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayHumanityJwt"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayHumanityJwt"] = True

    # if request.form.to_dict()["displayAgeRange"] == "displayAgeRangeFalse":
    #     wallet_provider_configuration["discoverCardsOptions"]["displayAgeRange"] = False
    # else:
    #     wallet_provider_configuration["discoverCardsOptions"]["displayAgeRange"] = True

    # if request.form.to_dict()["displayGender"] == "displayGenderFalse":
    #     wallet_provider_configuration["discoverCardsOptions"]["displayGender"] = False
    # else:
    #     wallet_provider_configuration["discoverCardsOptions"]["displayGender"] = True
    
    if request.form.to_dict()["displayTezotopia"] == "displayTezotopiaFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayTezotopia"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayTezotopia"] = True

    
    if request.form.to_dict()["displayChainborn"] == "displayChainbornFalse":
        wallet_provider_configuration["discoverCardsOptions"]["displayChainborn"] = False
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayChainborn"] = True

    # if request.form.to_dict()["displayExternalIssuer"] == "displayExternalIssuerFalse":
    #     wallet_provider_configuration["discoverCardsOptions"]["displayExternalIssuer"] = False
    # else:
    #     wallet_provider_configuration["discoverCardsOptions"]["displayExternalIssuer"] = True



    # Part 7 
    if request.form.to_dict()["isAllowed"] == "isAllowedFalse":
        wallet_provider_configuration["companySignature"]["isAllowed"] = False
    else:
        wallet_provider_configuration["companySignature"]["isAllowed"] = True

    wallet_provider_configuration["companySignature"]["CompanyKey"] = request.form.to_dict()["CompanyKey"]

    wallet_provider_configuration["companySignature"]["Companykid"] = request.form.to_dict()["Companykid"]



    try:
        issuers = json.loads(db.read_issuers_config(session["organisation"]))
    except TypeError:
        issuers = []
    if not issuers:
        wallet_provider_configuration["discoverCardsOptions"]["displayExternalIssuer"] = [
        ]
    else:
        wallet_provider_configuration["discoverCardsOptions"]["displayExternalIssuer"] = issuers
    file = request.files.get('file')
    if file and allowed_file(file.filename):
        img = Image.open(file)
        png_buffer = BytesIO()
        img.save(png_buffer, format="PNG")
        png_buffer.seek(0)
        png_file = png_buffer.read()
        image = Image.open(BytesIO(png_file))
        logo_file = generate_random_filename(20)
        image.save('./logos/'+logo_file+'.png')
        wallet_provider_configuration["generalOptions"]["companyLogo"] = "https://wallet-provider.talao.co/logo/" + logo_file
    else:
        logo = db.read_logo_url(
            session["organisation"])
        wallet_provider_configuration["generalOptions"]["companyLogo"] = logo
    db.update_config(json.dumps(wallet_provider_configuration),
                     session["organisation"])
    return redirect("/dashboard")


def dashboard():
    if request.MOBILE:
        return render_template("mobile.html")
    if not session.get("organisation"):
        return redirect("/")
    if session.get("organisation") == "Talao":
        session["organisation"] = request.args.get("organisation")
    if db.read_configured(session.get("organisation")) == 0:
        return redirect("/setup")
    plan = db.read_plan(session.get("organisation"))
    if plan == "paid":
        plan = ""
    users = db.read_users(session.get("organisation"))
    return render_template("dashboard.html", organisation=session.get("organisation"), rows=users, customer_plan=plan, version=VERSION)


def dashboard_talao():
    if session.get("organisation") != "Talao":
        return redirect("/")
    table = db.read_tables()
    return render_template("dashboard_talao.html", table=table, version=VERSION)


def add_user():
    if not session.get("organisation"):
        return "Unauthorized", 401
    if db.read_plan(session.get("organisation")) == "free":
        return "Unauthorized", 401
    email = request.get_json().get("email").lower().replace(" ", "")
    if len(email) == 0:
        return "Bad request", 400
    first_name = request.get_json().get("firstName")
    last_name = request.get_json().get("lastName")
    organisation = session["organisation"]
    password = generate_random_string(6)
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    db.create_user(email, sha256_hash, organisation, first_name, last_name)
    message.messageHTML(
        "Your altme password", email, 'password', {
            'code': str(password),
            'website':  mode.server + "configuration/webpage?login=" + email + "&password=" + str(password) + "&wallet-provider=" + mode.server
        }
    )
    return ("ok")

def generate_random_email():
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"guest@{random_part}.talao.co"

def add_user_guest():
    if not session.get("organisation"):
        return "Unauthorized", 401
    if db.read_plan(session.get("organisation")) == "free":
        return "Unauthorized", 401
    
    random_email = generate_random_email()  # Générer un email aléatoire
    password = generate_random_string(6)  # Générer un mot de passe aléatoire
    
    # Appeler create_user() avec les informations nécessaires
    db.create_user(random_email, password, session["organisation"], first_name="guest", last_name="guest")
    
    # Autres actions, comme l'envoi d'un email ou la réponse HTTP
    return "ok"
 

def add_organisation():
    if session.get("organisation") != "Talao":
        return "Unauthorized", 401
    organisation = request.get_json().get("organisation")
    email = request.get_json().get("emailAdmin").lower().replace(" ", "")
    if len(organisation) == 0 or len(email) == 0:
        return "Bad request", 400
    first_name = request.get_json().get("firstNameAdmin")
    last_name = request.get_json().get("lastNameAdmin")
    company_name = request.get_json().get("companyName")
    password = generate_random_string(6)
    if len(email.split("@")) < 2:
        return "Bad request", 400
    if email.split("@")[1] == "wallet-provider.io":
        logging.info("demo organisation created")
        password = json.load(open("keys.json", "r"))["password_demo"]
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    if email.split("@")[1] != "wallet-provider.io":
        message.messageHTML("Your altme password", email,
                            'password_admin', {'code': str(password)})
    wallet_provider_configuration = json.load(
        open('./wallet-provider-configuration.json', 'r'))
    wallet_provider_configuration["generalOptions"]["companyName"] = company_name
    wallet_provider_configuration["generalOptions"]["companyName"] = company_name
    profileId = base64.b64encode(
        str(uuid.uuid1()).encode()).decode().replace("=", "")[:10]
    wallet_provider_configuration["generalOptions"]["profileId"] = profileId
    wallet_provider_configuration["generalOptions"]["published"] = datetime.today(
    ).strftime('%Y-%m-%d')
    db.create_organisation(organisation, json.dumps(
        wallet_provider_configuration))
    db.create_admin(email, sha256_hash, organisation, first_name, last_name)
    db.create_user(email, sha256_hash, organisation, first_name, last_name)
    return ("ok")


def delete_user():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    email = request.get_json().get("email")
    db.delete_user(email, organisation)
    return ("ok")


def send_message():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    thumbprint = db.read_thumbprint(
        request.get_json().get("email"), organisation)
    message = request.get_json().get("message")
    if thumbprint:
        headers = {
            'X-API-KEY': '8b807485-e19d-4d75-adfd-f8b47c97208b',
        }
        json_data = {
            'message': message,
            'did': thumbprint,
        }
        response = requests.post(
            'https://talao.co/matrix/send_message', headers=headers, json=json_data)
        if response.status_code == 200:
            logging.info("info sent to %s", thumbprint)
        else:
            pass
    else:
        logging.warning("no thumbprint")
    return ("ok")


def logout():
    session["organisation"] = None
    session["configured"] = None
    user_session = UserSession(flask.session)
    user_session.clear()
    session.clear()
    return ("ok")


def change_plan():
    if session.get("organisation") != "Talao":
        return "Unauthorized", 401
    organisation = request.get_json().get("organisation")
    newPlan = request.get_json().get("newPlan")
    db.update_plan(organisation, newPlan)
    return ("ok")


def change_status():
    email = request.get_json().get("email")
    if not email:
        return "Bad request", 400
    if not session.get("organisation") or db.read_organisation_user(email) != session.get("organisation"):
        return "Unauthorized", 401
    newStatus = request.get_json().get("newStatus")
    db.update_status_user(email, newStatus)
    return ("ok")


def delete_organisation():
    if session.get("organisation") != "Talao":
        return "Unauthorized", 401
    organisation = request.get_json().get("organisation")
    db.delete_organisation(organisation)
    return ("ok")


def update_status_organisation():
    if session.get("organisation") != "Talao":
        return "Unauthorized", 401
    organisation = request.get_json().get("organisation")
    new_status = request.get_json().get("new_status")
    db.update_status_organisation(organisation, new_status)
    return ("ok")


def update_password_admin():
    if session.get("organisation") != "Talao":
        return "Unauthorized", 401
    email = request.get_json().get("email")
    if email.split("@")[1] == "wallet-provider.io":
        return ("ok")
    password = generate_random_string(6)
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    message.messageHTML("Your altme password", email,
                        'password_admin', {'code': str(password)})
    db.update_password_admin(email, sha256_hash)
    return ("ok")


def update_password_user():
    email = request.get_json().get("email")
    if not session.get("organisation") or db.read_organisation_user(email) != session.get("organisation"):
        return "Unauthorized", 401
    if email.split("@")[1] == "wallet-provider.io":
        return str(db.read_data_user(email))
    password = generate_random_string(6)
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    message.messageHTML(
        "Your altme password", email, 'password', {
            'code': str(password),
            'website':  mode.server + "configuration/webpage?login=" + email + "&password=" + str(password) + "&wallet-provider=" + mode.server
        }
    )
    db.update_password_user(email, sha256_hash)
    return ("ok")


def alert_new_config():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    emails_list = db.read_email_users(organisation)
    for email in emails_list:
        message.message("Your " + organisation+" wallet",
                        email[0], "A new configuraiton is available. Update your wallet to use your new settings.")
    return "ok"


def alert_users():
    if not session.get("organisation"):
        return "Unauthorized", 401
    users = db.read_thumbprints(session.get("organisation"))
    message = request.get_json()["message"]
    headers = {
        'X-API-KEY': '8b807485-e19d-4d75-adfd-f8b47c97208b',
    }
    for user in users:
        logging.info(user)
        if user[0]:
            json_data = {
                'message': message,
                'did': user[0],
            }
            logging.info(str(json_data))
            response = requests.post(
                'https://talao.co/matrix/send_message', headers=headers, json=json_data)
            if response.status_code == 200:
                logging.info("info sent to %s", user[0])
            else:
                pass
                # logging.error(user[0])
    return "ok"


def add_issuer_db():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    id = str(uuid.uuid1())
    privacy = request.get_json()["privacyIssuer"]
    data = json.dumps(request.get_json()["data"])
    db.create_issuer(id, organisation, data, privacy)
    return ("ok")


def modify_issuer_db():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    privacy = request.get_json()["privacyIssuer"]
    data = json.dumps(request.get_json()["data"])
    id = request.get_json()["id"]
    db.update_issuer(id, data,organisation,privacy)
    return ("ok")


def remove_issuer_db():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    id = request.get_json()["id"]
    db.delete_issuer(id, organisation)
    return "ok"


def get_issuer_infos(id):
    if not session.get("organisation"):
        return "Unauthorized", 401
    infos = json.loads(db.read_issuer(id)[0])
    infos["privacy"] = db.read_issuer(id)[1]
    return infos   

def change_issuer_config():
    if not session.get("organisation"):
        return "Unauthorized", 401
    organisation = session.get("organisation")
    new_status = request.get_json()["newStatus"]
    id = request.get_json()["id"]
    print("status=",new_status, "id=",id)
    if new_status == "visible":
        config = db.read_config_from_organisation(organisation)
        issuer = json.loads(db.read_issuer(id)[0])
        issuerFormated = {
            "title":issuer["title"],
            "subtitle":issuer["subtitle"],
            "description":issuer["description"],
            "how_to_get_it":issuer["howToGetIt"],
            "validity_period":issuer["expirationDate"],
            "category":issuer["category"],
            "name":issuer["name"],
            "redirect":issuer["url"],
            "background_image":issuer["background_url"],
            "logo":issuer["logo_url"],
            "background_color":issuer["background_color"],
            "text_color":issuer["text_color"],
            "issuer_id":id,
        }
        config["discoverCardsOptions"]["displayExternalIssuer"].append(issuerFormated)
        print(config["discoverCardsOptions"]["displayExternalIssuer"])
        db.update_config(json.dumps(config), organisation)
    elif new_status == "invisible":
        config = db.read_config_from_organisation(organisation)
        config["discoverCardsOptions"]["displayExternalIssuer"] = [d for d in config["discoverCardsOptions"]["displayExternalIssuer"] if d.get("issuer_id") != id]
        print(config["discoverCardsOptions"]["displayExternalIssuer"])
        db.update_config(json.dumps(config), organisation)
    return "ok"

def store_key(key, kid):
    try:
        FERNET_KEY = json.load(open('keys.json', 'r'))['fernet_key']
    except Exception:
        return
    f = Fernet(FERNET_KEY)
    key = json.dumps(key) if isinstance(key, dict) else key
    encrypted_company_key = f.encrypt(key.encode())
    with open('keystore/' + kid + '.txt', 'w') as outfile:
        outfile.write(encrypted_company_key.decode())
    return True

init_app(app, red)
wallet_provider.init_app(app, red, mode)

if __name__ == '__main__':
    logging.info("app init")

    app.run(host=mode.IP, port=mode.port, debug=True)
