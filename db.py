import sqlite3
from hashlib import sha256
import logging

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


def verify_password_admin(email, password):
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation'),configured from admins,organisations where email='{email}' and json_extract(data,'$.password')='{password}' and json_extract(data,'$.organisation')=name".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return [rows[0][0], rows[0][1]]


def verify_password_user(email, password):
    password = sha256(password.encode('utf-8')).hexdigest()
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select json_extract(data,'$.organisation') from users where email ='{email}' and json_extract(data,'$.password') = '{password}'".format(
        email=email, password=password))
    rows = c.fetchall()
    if len(rows) < 1:
        return False
    return True


def update_config(config, organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    print("update organisations set configured=1 , config=('{config}') where name='{organisation}'".format(
        config=config, organisation=organisation))
    c.execute("update organisations set configured=1 , config=('{config}') where name='{organisation}'".format(
        config=config, organisation=organisation))
    conn.commit()


def read_configured(organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT configured FROM organisations where  name = '{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    return [rows[0][0]]


def create_user(email, password, organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    data = '{"password": "'+password+'", "organisation": "'+organisation+'"}'
    c.execute("""insert into users values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()


def read_users(organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT email  FROM users as email where json_extract(data,'$.organisation')='{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    return rows


def update_data_user(email, data):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('update users set data={data}  where email="{email}"'.format(
        data=data, email=email))
    conn.commit()


def read_config(email):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("select config from organisations,users where name=json_extract(data,'$.organisation') and email='{email}'".format(
        email=email))
    rows = c.fetchall()
    return [rows[0][0]]


def create_organisation(name):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("""insert into organisations values ('{name}',NULL,0)""".format(
        name=name))
    conn.commit()


def create_admin(email, password, organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    data = '{"password": "'+password+'", "organisation": "'+organisation+'"}'
    c.execute("""insert into admins values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()


# email => config
# ajouter thumbprint du wallet à data du user
