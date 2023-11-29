import uuid
import json
from flask import jsonify, request, Response
from datetime import datetime
import logging
from jwcrypto import jwk, jwt
import base64
import copy
import sys

import db # db manager for wallet-provider

logging.basicConfig(level=logging.INFO)

try:
    WALLET_PROVIDER_KEY = json.load(open("keys.json", "r"))['wallet_provider_key']
except Exception:
    logging.info("wallet provider keys missing")
    sys.exit()

WALLET_PROVIDER_PUBLIC_KEY =  copy.copy(WALLET_PROVIDER_KEY)
del WALLET_PROVIDER_PUBLIC_KEY['d']
WALLET_PROVIDER_VM = "did:web:talao.co#key-2"
WALLET_PROVIDER_DID = "did:web:talao.co"


def init_app(app, red, mode):
    # endpoints for OpenId customer application
    app.add_url_rule('/nonce',  view_func=nonce, methods=['GET'], defaults={"red": red, "mode": mode})
    app.add_url_rule('/token',  view_func=wallet_attestation_endpoint, methods=['POST'], defaults={"red": red, "mode": mode})
    app.add_url_rule('/configuration',  view_func=configuration, methods=['POST'], defaults={"red": red, "mode": mode})


def manage_error(error, error_description, status=400):
    """
    Return error code to wallet
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # console
    logging.warning("manage error = %s", error_description)
    # wallet
    payload = {
        "error": error,
        "error_description": error_description,
    }
    headers = {"Cache-Control": "no-store", "Content-Type": "application/json"}
    return {"response": json.dumps(payload), "status": status, "headers": headers}


def get_payload_from_jwt(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def sign_jwt(nonce, payload, typ, aud=None, jti=True):
    header = {
        'typ':typ,
        'kid': WALLET_PROVIDER_VM,
        'alg': 'ES256'
    }
    data = {
        'iss': WALLET_PROVIDER_DID,
        'iat': datetime.timestamp(datetime.now().replace(second=0, microsecond=0)),
        "exp": datetime.timestamp(datetime.now().replace(second=0, microsecond=0)) + + 365*24*60*60
    }
    if nonce:
        data['nonce'] = nonce  
    if jti:
        data['jti'] = str(uuid.uuid1())
    if aud:
        data['aud'] = aud
    data.update(payload)

    token = jwt.JWT(header=header, claims=data, algs=['ES256'])
    signer_key = jwk.JWK(**WALLET_PROVIDER_KEY) 
    token.make_signed_token(signer_key)
    return token.serialize()


def nonce(red, mode):
    """
    API endpoint for wallet
    curl -X GET http://192.168.00.65:5000/nonce
    """
    nonce = str(uuid.uuid1())
    request.host
    red.setex(nonce, 30, request.host )
    return jsonify({'nonce': nonce})
  


def wallet_attestation_endpoint(red, mode):
    """

    https://italia.github.io/eudi-wallet-it-docs/versione-corrente/en/wallet-instance-attestation.html#id1


    POST /token HTTP/1.1
    Host: wallet-provider.talao.co
    Content-Type: application/x-www-form-urlencoded

    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    &assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6ImtoakZWTE9nRjNHeGRxd2xVTl9LWl83

    with assertion received =
    {
        "alg": "ES256",
        "kid": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
        "typ": "wiar+jwt"
    }
    {
        "iss": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
        "aud": "https://wallet-provider.altme.io",
        "jti": "6ec69324-60a8-4e5b-a697-a766d85790ea",
        "nonce" : ".....",
        "cnf": {
            "jwk": {
            "crv": "P-256",
            "kty": "EC",
            "x": "4HNptI-xr2pjyRJKGMnz4WmdnQD_uJSq4R95Nj98b44",
            "y": "LIZnSB39vFJhYgS3k7jXE4r3-CoGFQwZtPBIRqpNlrg",
            "kid": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c"
        }
    },
    "iat": 1686645115,
    "exp": 1686652315
    }
    
    """
    try:
        assertion = request.form['assertion']
        grant_type = request.form['grant_type']
    except Exception:
        return Response(**manage_error("invalid_request", "assertion or grant_type missing"))
    if grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        return Response(**manage_error("invalid_grant", "Assertion expected"))

    wallet_request = get_payload_from_jwt(assertion)

    # check asssertion signature TODO 
    #a = jwt.JWT.from_jose_token(wallet_request)
    #issuer_key = jwk.JWK(**dict_key)
    #a.validate(issuer_key)

    nonce = wallet_request['nonce']
    if not red.get(nonce):
        return Response(**manage_error("invalid_request", "Nonce expired"))
    
    payload = {
        "sub": wallet_request['iss'],
        "cnf": wallet_request['cnf'],
        "authorization_endpoint": "https://app.altme.io/app/download./authorize:",
        "response_types_supported": [
            "vp_token",
            "id_token"
        ],
        "response_modes_supported": [
            "form_post.jwt"
        ],
        "vp_formats_supported": {
            "vc+sd-jwt": {
                "sd-jwt_alg_values": [
                    "ES256",
                ]
            }
        },
        "request_object_signing_alg_values_supported": [
            "ES256"
        ],
        "presentation_definition_uri_supported": True,
    }   
    typ = "wallet-attestation+jwt"
    wallet_attestation = sign_jwt(nonce, payload, typ, jti=False)
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    return Response(wallet_attestation, headers=headers)



def configuration(red, mode):
    """
    POST /configuration HTTP/1.1
    Host: wallet-provider.talao.co
    Content-Type: application/x-www-form-urlencoded
    Authorization: Basic kjlgiutugigbioivi

    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    &assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6ImtoakZWTE9nRjNHeGRxd2xVTl9LWl83
    """
    try :
        Authorization = request.headers['Authorization']
        basic = base64.b64decode(Authorization.split()[1].encode()).decode()
        user_email = basic.split(':')[0]
        user_password = basic.split(':')[1]
        wallet_attestation = get_payload_from_jwt(request.form['assertion'])
    except Exception:
        return Response(**manage_error("invalid_request", "assertion or basic authentication missing"))

    # check user and password
    try :
        check = db.verify_password_user(user_email, user_password)
    except:
        return Response(**manage_error("server_error", "verify password failed"))
    if not check:
        Response(**manage_error("invalid_request", "user not found"))
    logging.info('logging/password is fine for %s', user_email)


    # Update user data with user jwk from wallet attestation
    try :
        user_jwk = wallet_attestation['cnf']['jwk']
        user_sub = wallet_attestation['sub']
    except Exception:
        return Response(**manage_error("invalid_request", "incorrect wallet attestation"))
    user_data = db.read_data_user(user_email) # -> dict
    if not user_data:
        return Response(**manage_error("invalid_request", "user not found"))
    user_data.update({"wallet_instance_key_thumbprint" : user_sub})
    try:
        check = db.update_data_user(user_email, json.dumps(user_data))
    except Exception:
        return Response(**manage_error("server_error", "user data update failed"))
    logging.info("user data update is done = %s", check)


    # Get configuration for user
    config = {}
    try:
        config = db.read_config(user_email) # -> dict
    except Exception:
            return Response(**manage_error("server_error", "incorrect configuration file"))
    if not config:
        return Response(**manage_error("invalid_request", "configuration is not found"))
    logging.info('configuration = %s', config)
    
    payload = sign_jwt(None, config, 'JWT')
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    return Response(payload, headers=headers)


