import uuid
import json
from flask import jsonify, request, Response, render_template
from datetime import datetime
import logging
from jwcrypto import jwk, jwt
import base64
import copy
import sys
import requests
import math
import message
import db # db manager for wallet-provider
from cryptography.fernet import Fernet


logging.basicConfig(level=logging.INFO)

try:
    WALLET_PROVIDER_KEY = json.load(open('keys.json', 'r'))['wallet_provider_key']
    FERNET_KEY = json.load(open('keys.json', 'r'))['fernet_key']
except Exception:
    logging.info('wallet provider key missing')
    sys.exit()

TRUSTED_LIST = ['did:web:talao.co']
WALLET_PROVIDER_PUBLIC_KEY =  copy.copy(WALLET_PROVIDER_KEY)
del WALLET_PROVIDER_PUBLIC_KEY['d']
WALLET_PROVIDER_VM = 'did:web:talao.co#key-2'
WALLET_PROVIDER_DID = 'did:web:talao.co'
WALLET_API_VERSION = '0.3.1'
ATTESTATION_DURATION = 365 # days

def get_key(kid):
    f = Fernet(FERNET_KEY)
    with open('keystore/' + kid + '.txt', 'r') as outfile :
        encrypted_issuer_key = outfile.read()
    return f.decrypt(encrypted_issuer_key.encode()).decode()


def alg(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key['kty'] == 'EC':
        if key['crv'] in ['secp256k1', 'P-256K']:
            key['crv'] = 'secp256k1'
            return 'ES256K' 
        elif key['crv'] == 'P-256':
            return 'ES256'
        else:
            raise Exception("Curve not supported")
    elif key['kty'] == 'RSA':
        return 'RS256'
    elif key['kty'] == 'OKP':
        return 'EdDSA'
    else:
        raise Exception("Key type not supported")
    
    
def init_app(app, red, mode):
    # endpoints for OpenId customer application
    app.add_url_rule('/nonce',  view_func=nonce, methods=['GET'], defaults={'red': red})
    app.add_url_rule('/token',  view_func=wallet_attestation_endpoint, methods=['POST'], defaults={'red': red})
    app.add_url_rule('/configuration',  view_func=wallet_configuration_endpoint, methods=['POST'])
    app.add_url_rule('/update',  view_func=wallet_update_endpoint, methods=['POST'])
    app.add_url_rule('/configuration/webpage',  view_func=wallet_configuration_webpage, methods=['GET', 'POST'])
    app.add_url_rule('/sign',  view_func=wallet_sign_endpoint, methods=['POST'])
    app.add_url_rule('/wallet_api_version',  view_func=wallet_api_version, methods=['GET'])


def thumbprint(key):
    signer_key = jwk.JWK(**key) 
    return signer_key.thumbprint()


def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += '=' * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def get_header_from_token(token):
    header = token.split('.')[0]
    header += '=' * ((4 - len(header) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(header).decode())


def resolve_did(vm) -> dict:
    did = vm.split('#')[0]
    url = 'https://unires.talao.co/1.0/identifiers/' + did
    try:
        r = requests.get(url, auth=('unires','test'))
        did_document = r.json()['didDocument']
        logging.info('Talao Universal Resolver used')
    except Exception:
        try:
            url = 'https://dev.uniresolver.io/1.0/identifiers/' + did
            r = requests.get(url)
            did_document = r.json()['didDocument']
            logging.info('DIF Universal Resolver used')
        except Exception:
            logging.error('Cannot access to resolvers')
            return
    for verification_method in did_document['verificationMethod']:
        if vm == verification_method['id'] or '#' + vm.split('#')[1] == verification_method['id']:
            jwk = verification_method.get('publicKeyJwk')
            if not jwk:
                publicKeyBase58 = verification_method.get('publicKeyBase58')
                logging.info('publiccKeyBase48 = %s', publicKeyBase58)
                return publicKeyBase58
            else:  
                logging.info('publicKeyJwk = %s', jwk)
                return jwk
    return


def verif_token(token):
    header = get_header_from_token(token)
    payload = get_payload_from_token(token)
    if header.get('typ') == 'wiar+jwt':
        dict_key = payload['cnf']['jwk']
    elif header.get('typ') == 'wallet-attestation+jwt':
        dict_key = resolve_did(header['kid'])
    else:
        raise Exception('Cannot resolve public key for this typ')
    if not dict_key:
        raise Exception('Cannot resolve public key')
    a = jwt.JWT.from_jose_token(token)
    issuer_key = jwk.JWK(**dict_key)
    a.validate(issuer_key)
    return True


def manage_error(error, error_description, status=400):
    """
    Return error code to wallet
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # console
    logging.warning('manage error = %s', error_description)
    # wallet
    payload = {
        "error": error,
        "error_description": error_description,
    }
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


def sign_jwt(payload, typ, nonce=None, aud=None, jti=None, duration=0):
    duration = duration * 24*60*60
    header = {
        'typ':typ,
        'kid': WALLET_PROVIDER_VM,
        'alg': alg(WALLET_PROVIDER_KEY)
    }
    data = {
        'iss': WALLET_PROVIDER_DID,
        'iat': math.floor(datetime.timestamp(datetime.now().replace(second=0, microsecond=0))),
    }
    if duration != 0: data['exp'] = math.floor(datetime.timestamp(datetime.now().replace(second=0, microsecond=0)) + duration)
    if nonce: data['nonce'] = nonce  
    if jti: data['jti'] = jti 
    if aud: data['aud'] = aud
    data.update(payload)
    token = jwt.JWT(header=header, claims=data, algs=[alg(WALLET_PROVIDER_KEY)])
    signer_key = jwk.JWK(**WALLET_PROVIDER_KEY) 
    try:
        token.make_signed_token(signer_key)
    except Exception:
        return
    return token.serialize()


def wallet_api_version():
    return jsonify(WALLET_API_VERSION)


def nonce(red):
    nonce = str(uuid.uuid1())
    red.setex(nonce, 10, request.host )
    logging.info('nonce is sent to wallet')
    return jsonify({'nonce': nonce})


def wallet_attestation_endpoint(red):
    """
    https://italia.github.io/eudi-wallet-it-docs/versione-corrente/en/wallet-instance-attestation.html#id1

    https://datatracker.ietf.org/doc/html/draft-looker-oauth-attestation-based-client-auth 

    """
    try:
        assertion = request.form['assertion']
        grant_type = request.form['grant_type']
    except Exception:
        return Response(**manage_error('invalid_request', 'assertion or grant_type missing'))
    if grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        return Response(**manage_error('invalid_grant', 'Assertion expected'))
    try:
        wallet_request = get_payload_from_token(assertion)
        wallet_cnf =  copy.copy(wallet_request['cnf'])
        wallet_cnf['jwk'].update({'kid': wallet_request['iss']})
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Assertion format is incorrect -> ' + str(e)))

    # check wallet request signature
    try:
        result = verif_token(assertion)
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Assertion signature check failed : ' + str(e)))
    if not result:
        return Response(**manage_error('invalid_request', 'Assertion signature check failed'))

    logging.info('wallet request signature is ok')
    
    # check wallet request nonce
    nonce = wallet_request['nonce']
    if not red.get(nonce):
        return Response(**manage_error('invalid_request', 'Nonce incorrect'))

    # build and send wallet attestation
    payload = {
        "sub": wallet_request['iss'],
        "cnf": wallet_cnf,
        "wallet_name": "Talao Altme wallet",
        "key_type" : "software",
        "authorization_endpoint": "https://app.altme.io/app/download/authorize",
        "response_types_supported": [
            "vp_token",
            "id_token"
        ],
        "request_object_signing_alg_values_supported": [
            "ES256",
            "ES256K"
        ],
        "presentation_definition_uri_supported": True,
    }   
    jti = str(uuid.uuid1())
    # TODO can store the jti 
    wallet_attestation = sign_jwt(payload, 'wallet-attestation+jwt', nonce=nonce, jti=jti)
    logging.info('Watte attestation = %s', wallet_attestation)
    if not wallet_attestation:
        return Response(**manage_error("server_error", "Wallet attestation failed to be signed"))
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    logging.info('wallet attestation is transfered to wallet')
    return Response(wallet_attestation, headers=headers)


def wallet_configuration_endpoint():
    try:
        Authorization = request.headers['Authorization']
        payload = Authorization.split()[1]
        try:
            basic = base64.urlsafe_b64decode(payload.encode()).decode()
            logging.info('No padding issue')
        except Exception:
            logging.info('Padding issue')
            payload += "=" * ((4 - len(payload) % 4) % 4)
            basic = base64.urlsafe_b64decode(payload.encode()).decode()
        user_email = basic.split(':')[0]
        user_password = basic.split(':')[1]
    except Exception as e:
        return Response(**manage_error('invalid_request', 'basic authentication missing or incorrect -> ' + str(e)))
    
    # is guest
    guest = (user_email.split("@")[0] == "guest")
    logging.info("guest is %s", guest )
    
    # check if user and password exist in the customer DB
    if not guest:
        try:
            check = db.verify_password_user(user_email, user_password)
        except Exception:
            return Response(**manage_error('server_error', 'verify_password_user DB call failed'))
        if not check:
            return Response(**manage_error('invalid_request', 'user not found'))
        logging.info('login/password is fine for %s', user_email)

    try:
        wallet_attestation = get_payload_from_token(request.form['assertion'])
    except Exception as e:
        return Response(**manage_error('invalid_request', 'assertion missing'))

    # check wallet attestation signature
    try:
        verif_token(request.form['assertion'])
        logging.info('wallet attestation signature is ok')
    except Exception:
        return Response(**manage_error('invalid_request', 'Wallet attestation signature check failed'))
    
    # check wallet attestation format and validity
    try:
        iss = wallet_attestation['iss']
        jti = wallet_attestation.get('jti')
        exp = wallet_attestation.get('exp')
        user_jwk = wallet_attestation['cnf']['jwk']
        user_sub = wallet_attestation['sub']
    except Exception:
        return Response(**manage_error('invalid_client', 'incorrect wallet attestation format')) 
    
    # check if this user has multiple wallet attestation
    if not guest:
        data_of_this_user = db.read_data_user(user_email)
        if data_of_this_user.get('wallet_instance_jti') and jti != data_of_this_user.get('wallet_instance_jti'):
            logging.warning('This user is already registered with another wallet attestation')
            message.message("This user is already registered with another wallet attestation", 'thierry.thevenet@talao.io', user_email + " is registering multiple configurations")
        else:
            #message.message("New enterprise wallet configuration", 'thierry.thevenet@talao.io', user_email + " is registering a new configuration")
            logging.info('This user is already registered with same wallet attestation')
    if iss not in TRUSTED_LIST:
        return Response(**manage_error('invalid_client', 'Wallet attestation is not issued by trusted wallet provider'))
    if exp and exp < datetime.timestamp(datetime.now().replace(second=0, microsecond=0)):
        return Response(**manage_error('invalid_request', 'Wallet attestation expired'))
    
    # check if user is suspended
    if not guest:
        status = data_of_this_user['status']
        logging.info("user status = %s", status)
        #if status != "active":
        #    return Response(**manage_error('invalid_client', 'User has been suspended'))

    # Update user data with user wallet attestation data
    if not guest:
        user_data = db.read_data_user(user_email) # -> dict
        if not user_data:
            return Response(**manage_error('invalid_client', 'user not found'))
        user_data.update(
            {        
                "wallet_instance_key_thumbprint": user_sub,
                "wallet_instance_jti": jti,
                "wallet_cnf_jwk": user_jwk,
                "attestation_iat": datetime.timestamp(datetime.now().replace(second=0, microsecond=0)),
            })
        try:
            db.update_data_user(user_email, json.dumps(user_data))
        except Exception:
            return Response(**manage_error('server_error', 'user data update failed'))
        logging.info('user data is now updated')

    # Build and sign configuration jwt for user wallet 
    try:
        config = db.read_config(user_email) # -> dict
    except Exception:
        return Response(**manage_error('server_error', 'incorrect configuration file'))
    if not config:
        return Response(**manage_error('invalid_request', 'configuration is not found for this user ' + user_email))
    
    # increment instance in organisation 
    try:
        if organisation := db.read_organisation_user(user_email):
            db.increment_instances(organisation)
    except Exception:
        logging.error("Cannot increment instances")

    # Check if organization is still active
    logging.info('Organization status = %s', config.get('organizationStatus', True))
    if not config.get('organizationStatus', True):
        return Response(**manage_error('invalid_client', 'This organization is suspended'))

    payload = sign_jwt(config, 'JWT', duration=90*24*60*60, jti=config['generalOptions']['profileId'] )
    if not payload:
        return Response(**manage_error('server_error', 'Configuration fails to be signed'))
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    logging.info('Configuration is sent to wallet = %s', payload)
    return Response(payload, headers=headers)


def wallet_configuration_webpage():
    login = request.args.get('login')
    password = request.args.get("password")
    wallet_provider = request.args.get("wallet-provider")
    if not login or not password or not wallet_provider:
        return jsonify("Unauthorized"), 404
    url = "configuration://?password=" + password + "&login=" + login + "&wallet-provider=" + wallet_provider
    return render_template("configure_qrcode.html", url=url)   


def wallet_update_endpoint():
    logging.info("Update request header = %s", request.headers)
    try:
        Authorization = request.headers['Authorization']
        payload = Authorization.split()[1]
        try:
            basic = base64.urlsafe_b64decode(payload.encode()).decode()
            logging.info('No padding issue')
        except Exception:
            logging.info('Padding issue')
            payload += "=" * ((4 - len(payload) % 4) % 4)
            basic = base64.urlsafe_b64decode(payload.encode()).decode()
        user_email = basic.split(':')[0]
        user_password = basic.split(':')[1]
    except Exception as e:
        return Response(**manage_error('invalid_request', 'basic authentication missing or incorrect -> ' + str(e)))
    
    # Get wallet attestation"
    try:
        wallet_attestation = get_payload_from_token(request.form['assertion'])
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Wallet attestation is missing'))

    # check wallet attestation signature
    try:
        verif_token(request.form['assertion'])
        logging.info('wallet attestation signature is ok')
    except Exception as e:
        return Response(**manage_error('invalid_client', 'Wallet attestation signature check failed'))
    
    # check wallet attestation validity and format
    try:
        iss = wallet_attestation['iss']
        exp = wallet_attestation.get('exp')
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Incorrect wallet attestation')) 
    if iss not in TRUSTED_LIST:
        return Response(**manage_error('invalid_request', 'Wallet attestation is not issued by a trusted wallet provider'))
    if exp and exp < datetime.timestamp(datetime.now().replace(second=0, microsecond=0)):
        return Response(**manage_error('invalid_request', 'Wallet attestation expired'))
    
    # get config 
    try:
        config = db.read_config(user_email) # -> dict
    except Exception:
        return Response(**manage_error('server_error', 'incorrect configuration file'))
    if not config:
        return Response(**manage_error('invalid_request', 'configuration is not found for this user ' + user_email))

    # Check if organization is still active
    logging.info('Organization status = %s', config.get('organizationStatus', True))
    if not config.get('organizationStatus', True):
        return Response(**manage_error('invalid_client', 'This organization is suspended'))
    
    # sign JWT config
    payload = sign_jwt(config, 'JWT', duration=90*24*60*60, jti=config['generalOptions']['profileId'] )
    if not payload:
        return Response(**manage_error('server_error', 'Configuration fails to be signed'))
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    logging.info('Configuration is sent to wallet for update')
    logging.info(payload)
    return Response(payload, headers=headers)


def wallet_sign_endpoint():
    try:
        wallet_attestation = get_payload_from_token(request.form['assertion'])
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Wallet attestation missing'))
    
    # check wallet attestation signature
    try:
        verif_token(request.form['assertion'])
        logging.info('wallet attestation signature is ok')
    except Exception as e:
        return Response(**manage_error('invalid_client', 'Wallet attestation signature check failed'))
    
    # check wallet attestation format and validity
    try:
        iss = wallet_attestation['iss']
        exp = wallet_attestation.get('exp')
        user_jwk = wallet_attestation['cnf']['jwk']
        kid = user_jwk['kid']
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Incorrect wallet attestation')) 
    
    if iss not in TRUSTED_LIST:
        return Response(**manage_error('invalid_request', 'Wallet attestation is not issued by trusted wallet provider'))
    if exp and exp < datetime.timestamp(datetime.now().replace(second=0, microsecond=0)):
        return Response(**manage_error('invalid_request', 'Wallet attestation expired'))
    
    # check if instance is active
    if not db.read_status_from_thumbprint(kid):
        logging.warning("instance is not suspended")
    
    # get organisation name
    organisation = db.read_organisation_from_thumbprint(kid)
    if not organisation:
        return Response(**manage_error('invalid_request', 'Organisaton not found'))

    # get config from organisation
    config = db.read_config_from_organisation(organisation)
    logging.info('company signature = %s', config['companySignature'])
    
    # get company key
    try:
        is_allowed = config['companySignature']['isAllowed']
        kid = config['companySignature']['kid']
    except Exception:
        kid = None
        is_allowed = False
    if not kid or not is_allowed:
        return Response(**manage_error('invalid_request', 'Company key not found'))
    company_key = json.loads(get_key(kid))
    signer_key = jwk.JWK(**company_key)
    
    # setup jwt header and payload
    logging.info("jwt_payload received from wallet = %s", jwt_payload)
    logging.info("jwt_header received from wallet = %s", jwt_header)
    jwt_payload = json.loads(request.form['jwt_payload'])
    jwt_payload['iss'] = kid.split('#')[0]
    jwt_header = json.loads(request.form['jwt_header'])
    jwt_header.update({
        "alg": company_key['alg'],
        "kid": kid
    })

    # sign jwt
    token = jwt.JWT(header=jwt_header, claims=jwt_payload, algs=[company_key["alg"]])
    token.make_signed_token(signer_key)
    payload = token.serialize()
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    logging.info('token signed is sent to wallet')
    logging.info(payload)
    return Response(payload, headers=headers)

