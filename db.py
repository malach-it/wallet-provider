import sqlite3
from hashlib import sha256
import logging
import json


conn = sqlite3.connect('db.sqlite')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS admins (
             email TEXT PRIMARY KEY,
             data TEXT
          )''')
c.execute('''CREATE TABLE IF NOT EXISTS organisations (
             id TEXT PRIMARY KEY,
             config TEXT,
          configured INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS users (
             email TEXT PRIMARY KEY,
             data TEXT)''')
conn.commit()


def verify_password_admin(email: str, password: str) -> list:
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation'),configured from admins,organisations where email='{email}' and json_extract(data,'$.password')='{password}' and json_extract(data,'$.organisation')=name".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return [rows[0][0], rows[0][1]]


def verify_password_user(email: str, password: str) -> bool:
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from users where email ='{email}' and json_extract(data,'$.password') = '{password}'".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return True


def create_admin(email: str, password: str, organisation: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    data = '{"password": "'+password+'", "organisation": "'+organisation+'"}'
    c.execute("""insert into admins values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()
    return True


def create_user(email: str, password: str, organisation: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    data = '{"password": "'+password+'", "organisation": "'+organisation+'"}'
    c.execute("""insert into users values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()
    return True


def create_organisation(name: str) -> bool:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("""insert into organisations values ('{name}',NULL,0)""".format(
        name=name))
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
    c.execute("SELECT email  FROM users as email where json_extract(data,'$.organisation')='{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return rows


def read_data_user(email: str) -> dict:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select data from users where email='{email}'".format(
        email=email))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return json.loads(rows[0][0])


def read_config(email: str) -> dict:
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select config from organisations,users where name=json_extract(data,'$.organisation') and email='{email}'".format(
        email=email))
    rows = c.fetchall()
    if len(rows) < 1:
        return None
    return json.loads(rows[0][0])


def verify_password_admin(email: str, password: str) -> list:
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation'),configured from admins,organisations where email='{email}' and json_extract(data,'$.password')='{password}' and json_extract(data,'$.organisation')=name".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return [rows[0][0], rows[0][1]]


def verify_password_user(email: str, password: str) -> bool:
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from users where email ='{email}' and json_extract(data,'$.password') = '{password}'".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return True


# ajouter thumbprint du wallet à data du user
