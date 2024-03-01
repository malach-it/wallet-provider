import sqlite3
from hashlib import sha256
import logging
import json
import time
logging.basicConfig(level=logging.INFO)


conn = sqlite3.connect('db.sqlite')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS admins (
             email TEXT PRIMARY KEY,
             data TEXT
          )''')
c.execute('''CREATE TABLE IF NOT EXISTS organisations (
             name TEXT PRIMARY KEY,
             config TEXT,
          configured INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS users (
             email TEXT PRIMARY KEY,
             data TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS issuers (
             id TEXT PRIMARY KEY,
          organisation TEXT,
             data TEXT,
          privacy text)''')
conn.commit()


def verify_password_admin(email: str, password: str) -> bool:
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from admins where email='{email}' and json_extract(data,'$.password')='{password}'".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return True


def verify_password_user(email: str, password: str) -> bool:
    if not password or not email:
        return False
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from users where email ='{email}' and json_extract(data,'$.password') = '{password}'".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return True


def create_admin(email: str, password: str, organisation: str, first_name: str, last_name: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    data = '{"password": "'+password+'", "organisation": "'+organisation + \
        '","first_name":"'+first_name+'","last_name":"'+last_name+'"}'
    c.execute("""insert into admins values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()
    return True


def create_user(email: str, password: str, organisation: str, first_name: str, last_name: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    timestamp = int(time.time())
    data = '{"password": "'+password+'", "organisation": "'+organisation + \
        '","first_name":"'+first_name+'","last_name":"'+last_name + \
        '","status":"active","creation":"'+str(timestamp)+'"}'
    c.execute("""insert into users values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()
    return True


def create_issuer(id: str, organisation: str, data: dict, privacy: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("""insert into issuers values ('{id}','{organisation}','{data}','{privacy}')""".format(
        id=id, organisation=organisation, data=data, privacy=privacy))
    conn.commit()
    return True


def read_issuers_availables(organisation, issuers):
    issuers = str(issuers).replace("[", "(").replace("]", ")")
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(
        'select id,organisation,json_extract(data,"$.title") as title,json_extract(data,"$.subtitle") as subtitle,\
json_extract(data,"$.category") as category,json_extract(data,"$.format") as format,json_extract(data,"$.url") as url,\
json_extract(data,"$.name") as name,privacy,organisation="{organisation}" as owner,\
CASE WHEN id IN {issuers} THEN 1 ELSE 0 END AS is_in_set , case when organisation="{organisation}" then 1 else 0 end as owner \
from issuers where organisation="{organisation}" or privacy="public"'.format(organisation=organisation, issuers=issuers))
    rows = c.fetchall()
    return rows


def read_issuer(id):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select data,privacy from issuers where id ='{id}'".format(id=id))
    rows = c.fetchone()
    return rows

def create_organisation(name: str, config: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(
        """insert into organisations values ('{name}','{config}',0, 0)""".format(name=name, config=config))
    conn.commit()
    return True


def update_config(config: str, organisation: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update organisations set configured=1 , config=('{config}') where name='{organisation}'".format(
        config=config, organisation=organisation))
    conn.commit()
    return True


def update_data_user(email: str, data: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update users set data='{data}'  where email='{email}'".format(
        data=data, email=email))
    conn.commit()
    return True


def read_configured(organisation: str) -> int:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT configured FROM organisations where  name = '{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows[0][0]


def read_users(organisation: str) -> list:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT email, json_extract(data,'$.first_name') as first_name, json_extract(data,'$.last_name') as last_name,json_extract(data,'$.status') as status,strftime('%Y-%m-%d', json_extract(data,'$.creation'), 'unixepoch') as creation FROM users where json_extract(data,'$.organisation')='{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return []
    return rows


def read_plan(organisation: str) -> str:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(config,'$.generalOptions.customerPlan') from organisations where name ='{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows[0][0]


def read_data_user(email: str) -> dict:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select data from users where email='{email}'".format(
        email=email))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return json.loads(rows[0][0])


def read_thumbprints(organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.wallet_instance_key_thumbprint'),email from users where json_extract(data,'$.organisation')='{organisation}'".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows


def read_thumbprint(email: str, organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.wallet_instance_key_thumbprint') from users where email ='{email}' and json_extract(data,'$.organisation')='{organisation}'".format(
        email=email, organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows[0][0]


def read_email_users(organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT email from users where json_extract(data,'$.organisation') = '{organisation}'".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows


def read_organisation(email: str) -> str:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from admins where email='{email}'".format(
        email=email))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows[0][0]


def read_organisation_user(email: str) -> str:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from users where email='{email}'".format(
        email=email))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows[0][0]


def read_logo_url(organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()

    c.execute("select json_extract(config,'$.generalOptions.companyLogo') from organisations where name='{organisation}'".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows[0][0]


def read_status_from_thumbprint(thumbprint):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.status') from users where json_extract(data,'$.wallet_instance_key_thumbprint')='{thumbprint}'".format(
        thumbprint=thumbprint))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    if rows[0][0] == "active":
        return True
    return False


def instances(organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    db_data = { 'organisation': organisation}
    c.execute('SELECT instances FROM organisations WHERE name =:organisation ', db_data)
    client_data = c.fetchone()
    if not client_data[0]:
        conn.close()
        return 0
    conn.close()
    return client_data[0]


def increment_instances(organisation):
    i = instances(organisation) + 1
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    db_data = { 'organisation': organisation,
               "instance_number": i}
    try:
        c.execute("UPDATE organisations SET instances = :instance_number WHERE name =:organisation ", db_data)
    except Exception:
        return None
    conn.commit()
    conn.close() 


def read_organisation_from_thumbprint(thumbprint):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from users where json_extract(data,'$.wallet_instance_key_thumbprint')='{thumbprint}'".format(
        thumbprint=thumbprint))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return rows[0][0]


def read_config(email: str) -> dict:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select config from organisations,users where name=json_extract(data,'$.organisation') and email='{email}'".format(
        email=email))
    rows = c.fetchall()
    if len(rows) < 1 or rows[0][0] == None:
        return None
    config = json.load(open('./wallet-provider-configuration.json', 'r'))
    config = merge_dicts(config, json.loads(rows[0][0]))
    return config


def read_config_from_organisation(organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select config from organisations where name='{organisation}'".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1 or rows[0][0] == None:
        return None
    config = json.load(open('./wallet-provider-configuration.json', 'r'))
    config = merge_dicts(config, json.loads(rows[0][0]))
    return config


def read_tables():
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('SELECT email, json_extract(data, "$.organisation") AS organisation, '
              'json_extract(data, "$.password") AS password, name, configured, '
              'json_extract(config, "$.generalOptions.customerPlan") AS plan, '
              'json_extract(config, "$.generalOptions.organizationStatus") AS status, '
              'json_extract(config, "$.version") AS version, instances '
              'FROM admins, organisations '
              'WHERE json_extract(data, "$.organisation") = name')
    rows = c.fetchall()
    return rows


def delete_user(email: str, organisation: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("delete from users where email='{email}' and json_extract(data,'$.organisation')='{organisation}'".format(
        organisation=organisation, email=email))
    conn.commit()
    return True


def delete_organisation(organisation: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("delete from organisations   where name='{organisation}'".format(
        organisation=organisation))
    c.execute("delete from  admins where  json_extract(data,'$.organisation')='{organisation}'".format(
        organisation=organisation))
    c.execute("delete from  users where  json_extract(data,'$.organisation')='{organisation}'".format(
        organisation=organisation))
    conn.commit()
    return True


def update_password_admin(email, password):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update admins set data = json_set(data,'$.password','{password}')   where email='{email}'".format(
        email=email, password=password))
    conn.commit()
    return True


def update_password_user(email, password):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update users set data = json_set(data,'$.password','{password}')   where email='{email}'".format(
        email=email, password=password))
    conn.commit()
    return True


def update_status_user(email, status):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update users set data = json_set(data,'$.status','{status}')   where email='{email}'".format(
        email=email, status=status))
    conn.commit()
    return True


def update_status_organisation(organisation, status):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    if status == "active":
        status = "json('true')"
    else:
        status = "json('false')"
    c.execute("update organisations set config = json_set(config,'$.generalOptions.organizationStatus',{status})   where name='{organisation}'".format(
        organisation=organisation, status=status))
    conn.commit()
    return True


def update_plan(organisation, newPlan):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update organisations set config=json_set(config, '$.generalOptions.customerPlan', '{newPlan}')   where name='{organisation}'".format(
        newPlan=newPlan, organisation=organisation))
    conn.commit()
    return True


def read_issuers(organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(config,'$.discoverCardsOptions.displayExternalIssuer') from organisations where name='{organisation}'".format(
        organisation=organisation))
    rows = c.fetchone()
    issuers_ids = []
    try:
        for row in json.loads(rows[0]):
            try:
                issuers_ids.append(row["issuer_id"])
            except KeyError:
                pass
    except TypeError:
        pass
    return issuers_ids


def read_issuers_config(organisation: str):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(config,'$.discoverCardsOptions.displayExternalIssuer') from organisations where name='{organisation}'".format(
        organisation=organisation))
    rows = c.fetchone()
    return rows[0]


def update_issuer(id, data, organisation,privacy):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("update issuers set data = '{data}' , privacy = '{privacy}'  where id='{id}' and organisation='{organisation}'".format(
        id=id, data=data, organisation=organisation,privacy=privacy))
    conn.commit()
    return True


def delete_issuer(id, organisation) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("delete from issuers where id='{id}' and organisation='{organisation}'".format(
        organisation=organisation, id=id))
    conn.commit()
    return True


def merge_dicts(d1, d2):
    merged = d1.copy()
    for key, value in d2.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged

