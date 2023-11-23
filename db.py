import sqlite3

conn = sqlite3.connect('db.sqlite')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS admins (
             email TEXT PRIMARY KEY,
             password TEXT,
             organisation_id TEXT
          )''')

c.execute('''CREATE TABLE IF NOT EXISTS organisations (
             id TEXT PRIMARY KEY,
             config TEXT,
          configured INTEGER)''')

c.execute('''CREATE TABLE IF NOT EXISTS users (
             email TEXT PRIMARY KEY,
             data TEXT)''')

conn.commit()


def verify_password(email, password):
    print(email, password)
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT organisation_name,configured FROM admins,organisations where email = '{email}' and password = '{password}' and organisation_name=name".format(
        email=email, password=password))
    rows = c.fetchall()
    return [rows[0][0], rows[0][1]]


def update_config(config, organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('update organisations set configured=1 , config=("{config}") where name="{organisation}"'.format(
        config=config, organisation=organisation))
    conn.commit()


def is_configured(organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT configured FROM organisations where  name = '{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    return [rows[0][0]]


def add_user(email, password, organisation):
    print((email, password, organisation))
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    data = '{"password": "'+password+'", "organisation": "'+organisation+'"}'
    c.execute("""insert into users values ('{email}','{data}')""".format(
        email=email, data=data))
    conn.commit()


def get_users(organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT email  FROM users as email where json_extract(data,'$.organisation')='{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    return rows

def set_data_user(email,data):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute('update users set data={data}  where email="{email}"'.format(
        data=data, email=email))
    conn.commit()

def get_config(organisation):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute("SELECT config FROM organisations where name = '{organisation}' ".format(
        organisation=organisation))
    rows = c.fetchall()
    return [rows[0][0]]

print(get_config("France"))