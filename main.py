from flask import Flask, render_template, request, jsonify, redirect, session, Response, send_file
import flask
from flask_qrcode import QRcode
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


def generate_random_string(length):
    characters = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return ''.join(random.choice(characters) for _ in range(length))


logging.basicConfig(level=logging.INFO)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'achille'
mode = environment.currentMode(myenv)

app = Flask(__name__)
QRcode(app)
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
sess = Session()
sess.init_app(app)
"""
Init OpenID Connect client PYOIDC with the 3 bridge parameters :  client_id, client_secret and issuer URL
"""

client_metadata = ClientMetadata(
    client_id='hvxitrgzbc',
    client_secret="6ac16c6b-8882-11ee-a9b2-0a1628958560",
    # post_logout_redirect_uris=['http://127.0.0.1:4000/logout']
    # your post logout uri (optional)
)
provider_config = ProviderConfiguration(issuer='https://talao.co/sandbox/verifier/app',
                                        client_metadata=client_metadata)
auth = OIDCAuthentication({'default': provider_config}, app)

red = redis.Redis(host='127.0.0.1', port=6379, db=0)


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
    app.add_url_rule('/',  view_func=login,
                     methods=['GET'])
    app.add_url_rule('/login_password',  view_func=login_password,
                     methods=['POST'])
    app.add_url_rule('/dashboard',  view_func=dashboard,
                     methods=['GET'])
    app.add_url_rule('/setup',  view_func=setup,
                     methods=['GET'])
    app.add_url_rule('/set_config', view_func=set_config, methods=['POST'])
    app.add_url_rule('/add_user', view_func=add_user, methods=['POST'])

    return


# @auth.oidc_auth('default')
def login():
    """user_session = UserSession(flask.session)
    logging.info(get_payload_from_token(
        user_session.userinfo["vp_token_payload"]["vp"]["verifiableCredential"][0]))
    session["email"] = get_payload_from_token(
        user_session.userinfo["vp_token_payload"]["vp"]["verifiableCredential"][0])"""
    session["email"] = "e@e.com"
    return (render_template("login.html"))


def login_password():
    password = request.get_json().get("password")
    verif = db.verify_password(session.get("email"), password)
    organisation = verif[0]
    configured = verif[1]
    if not organisation:
        return "Not found", 404
    elif organisation == "Talao":
        return "Talao", 200
    else:
        session["organisation"] = organisation
        session["configured"] = configured
        return {"organisation": organisation, "configured": configured}, 200


def setup():
    if not session.get("organisation") or session.get("organisation") == "Talao":
        return "Unauthorized", 401
    organisation = session["organisation"]
    return render_template("setup.html")


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower(
           ) in app.config['ALLOWED_EXTENSIONS']


def set_config():
    print(request.form.to_dict())

    file = request.files.get('file')

    if file and allowed_file(file.filename):
        filename = session["organisation"] + \
            "."+file.filename.rsplit('.', 1)[1].lower()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    db.update_config(request.form.to_dict(), session["organisation"])
    return redirect("/dashboard")


def dashboard():
    if not session.get("organisation"):
        return "Unauthorized", 401
    if db.is_configured(session.get("organisation")) == 0:
        return redirect("/setup")
    users = db.get_users(session.get("organisation"))
    print(users)
    return render_template("dashboard.html", organisation=session.get("organisation"),rows=users)


def add_user():
    email = request.get_json().get("email")
    organisation = session["organisation"]
    password = generate_random_string(10)
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    print(password)
    print(sha256_hash)
    db.add_user(email, sha256_hash, organisation)
    message.messageHTML("Your altme password", email,
                        'code_auth_en', {'code': str(password)})

    return ("ok")


init_app(app, red)


if __name__ == '__main__':
    logging.info("app init")

    app.run(host=mode.IP, port=mode.port, debug=True)
