import sqlite3
import os
from sqlite3.dbapi2 import Connection
from OpenSSL import crypto
import open_ssl_wrapper as osw
import uuid as u

LZ_HUB_DB_PATH          = './lz_hubs.db'
TEST_CERTS_PATH         = './unit_test/test_certs/'

CREATE_STATEMENTS = {
    'devices': 'CREATE TABLE "devices" ('
        '`uuid`	BLOB, '
        '`name`	TEXT, '
        '`device_id_cert`	BLOB, '
        '`alias_id_cert`	BLOB, '
        '`awdt_period_s`	INTEGER, '
        '`status`	INTEGER, '
        '`data_index`	INTEGER, '
        '`temperature`	REAL, '
        '`humidity`	REAL, '
       'PRIMARY KEY(`uuid`)'
    ')',
    'logging': 'CREATE TABLE "logging" ('
        '`index`	INTEGER PRIMARY KEY AUTOINCREMENT, '
        '`timestamp`	TEXT, '
        '`temperature`	REAL, '
        '`humidity`	REAL '
    ')',
    'static_symms': 'CREATE TABLE "static_symms" ('
        '`uuid`	TEXT, '
        '`static_symm`	BLOB '
    ')',
}

def check_if_tables_exist(db: Connection):
    cursor = db.cursor()
    for (table_name, statement) in CREATE_STATEMENTS.items():
        sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=:name"
        data = {"name": table_name}
        cursor = db.cursor()
        result = cursor.execute(sql, data)
        if not result.fetchone():
            cursor.execute(statement)
            db.commit()
            print(f"Added table {table_name} to database.")


def connect():
    try:
        db = sqlite3.connect(LZ_HUB_DB_PATH)
        check_if_tables_exist(db)
        return db
    except sqlite3.Error as e:
        print("ERROR: Failed to connect to lazarus database: %s" %e.args)
        return None


def close(db):
    if db:
        db.close()
    else:
        print("ERROR: Could not close lazarus database connect: Connection was not open")


def insert_device(db, uuid, name, device_id_cert, static_symm):

    # Check if device in devices table exists
    try:
        cursor = db.cursor()
        sql = "SELECT EXISTS(SELECT 1 FROM devices WHERE uuid=?)"
        data = (uuid, )
        cursor.execute(sql, data)
        rows = cursor.fetchone()
        exists = rows[0]
    except sqlite3.Error as e:
        print("ERROR: Failed to query if device exists in db: %s" %(e.args))
        return False

    if exists == 1:
        # If it does exist, update the entry
        print("Device already exists, update device in devices table")
        try:
            cursor = db.cursor()
            sql = """UPDATE devices SET name=?, device_id_cert=? WHERE uuid=?"""
            data = (name, device_id_cert, uuid)
            cursor.execute(sql, data)
            db.commit()
        except sqlite3.Error as e:
            print("ERROR: Failed to update data in lazarus db: %s" %(e.args))
            return
    else:
        # If it does not exist, create the entry
        print("Device does not exist. Create new db entry in devices table")
        try:
            cursor = db.cursor()
            sql = "INSERT INTO devices (uuid, name, device_id_cert) VALUES (?, ?, ?)"
            data = (uuid, name, device_id_cert)
            cursor.execute(sql, data)
            db.commit()
        except sqlite3.Error as e:
            print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
            return False

    # Check if device exists in static_symm table
    try:
        cursor = db.cursor()
        sql = "SELECT EXISTS(SELECT 1 FROM static_symms WHERE uuid=?)"
        data = (uuid, )
        cursor.execute(sql, data)
        rows = cursor.fetchone()
        exists = rows[0]
    except sqlite3.Error as e:
        print("ERROR: Failed to query if device exists in db: %s" %(e.args))
        return False

    if exists == 1:
        # If it does exist, update the entry
        print("Device already exists, update device in static_symm table")
        try:
            cursor = db.cursor()
            sql = """UPDATE static_symms SET static_symm=? WHERE uuid=?"""
            data = (static_symm, uuid)
            cursor.execute(sql, data)
            db.commit()
        except sqlite3.Error as e:
            print("ERROR: Failed to update data in lazarus db: %s" %(e.args))
            return
    else:
        # Insert static sym into static_symms db
        print("Device does not exist. Create new db entry in static_symm table")
        try:
            cursor = db.cursor()
            sql = "INSERT INTO static_symms (uuid, static_symm) VALUES (?, ?)"
            data = (uuid, static_symm)
            cursor.execute(sql, data)
            db.commit()
        except sqlite3.Error as e:
            print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
            return False

    return True


def update_alias_id_cert(db, uuid, alias_id_cert):
    try:
        cursor = db.cursor()
        sql = """UPDATE devices SET alias_id_cert=? WHERE uuid=?"""
        data = (alias_id_cert, uuid)
        cursor.execute(sql, data)
        db.commit()
    except sqlite3.Error as e:
        print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
        return


def update_device_id_cert(db, uuid, device_id_cert):
    try:
        cursor = db.cursor()
        sql = """UPDATE devices SET device_id_cert=? WHERE uuid=?"""
        data = (device_id_cert, uuid)
        cursor.execute(sql, data)
        db.commit()
    except sqlite3.Error as e:
        print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
        return


def update_awdt_period(db, uuid, awdt_period_s):
    try:
        cursor = db.cursor()
        sql = """UPDATE devices SET awdt_period_s=? WHERE uuid=?"""
        data = (awdt_period_s, uuid)
        cursor.execute(sql, data)
        db.commit()
    except sqlite3.Error as e:
        print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
        return


def update_data(db, uuid, status, index, temperature, humidity):
    try:
        cursor = db.cursor()
        sql = """UPDATE devices SET status=?, data_index=?, temperature=?, humidity=? WHERE uuid=?"""
        data = (status, index, temperature, humidity, uuid)
        cursor.execute(sql, data)
        db.commit()
    except sqlite3.Error as e:
        print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
        return


def get_device_info(db, uuid):
    try:
        cursor = db.cursor()
        sql = "SELECT name, awdt_period_s, status, data_index, temperature, humidity FROM devices WHERE uuid=?"
        data = (uuid, )
        cursor.execute(sql, data)
        rows = cursor.fetchone()
        (name, awdt_period_s, status, index, temperature, humidity) = rows
    except sqlite3.Error as e:
        print("ERROR: Failed to retrieve data from lazarus db: %s" %(e.args))
        return None
    return name, awdt_period_s, status, index, temperature, humidity


def get_device_info_all(db):
    try:
        cursor = db.cursor()
        sql = "SELECT uuid, name, device_id_cert, alias_id_cert, awdt_period_s, status, data_index, temperature, humidity FROM devices"
        cursor.execute(sql)
        rows = cursor.fetchall()
    except sqlite3.Error as e:
        print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
        return None
    return rows


def get_uuids(db):
    try:
        cursor = db.cursor()
        sql = "SELECT uuid FROM devices"
        cursor.execute(sql)
        rows = cursor.fetchall()
    except sqlite3.Error as e:
        print("ERROR: Failed to insert data into lazarus db: %s" %(e.args))
        return None
    return [uuid[0] for uuid in rows]


def get_device_certs(db, uuid):
    try:
        cursor = db.cursor()
        sql = "SELECT device_id_cert, alias_id_cert FROM devices WHERE uuid=?"
        # uuid_string = uuid.decode("utf-8")
        data = (uuid, )
        cursor.execute(sql, data)
        rows = cursor.fetchone()
        (device_id_cert, alias_id_cert) = rows
    except sqlite3.Error as e:
        print("ERROR: Failed to retrieve data from lazarus db: %s" %(e.args))
        return None, None
    except Exception as e:
        print("ERROR: Failed to retrieve data from lazarus db: %s" %str(e))
        return None, None
    return device_id_cert, alias_id_cert


def get_static_symm(db, uuid):
    try:
        cursor = db.cursor()
        sql = "SELECT static_symm FROM static_symms WHERE uuid=?"
        data = (uuid, )
        cursor.execute(sql, data)
        rows = cursor.fetchone()
        (static_symm, ) = rows
    except sqlite3.Error as e:
        print("ERROR: Failed to retrieve data from lazarus db: %s" %(e.args))
        return None
    return static_symm


def set_hub_certs(db, hub_cert, hub_sk, code_auth_cert, code_auth_sk):
    raise NotImplementedError


def get_hub_certs(db, uuid):
    raise NotImplementedError


############################
########## TEST ############
############################


def test():
    db = connect()

    # Read test data
    try:
        with open(TEST_CERTS_PATH + "hub_cert.pem", "rb") as f:
            hub_cert = f.read()
        with open(TEST_CERTS_PATH + "alias_id_cert.pem", "rb") as f:
            alias_id_cert = f.read()
        with open(TEST_CERTS_PATH + "code_auth_cert.pem", "rb") as f:
            code_auth_cert = f.read()
        with open(TEST_CERTS_PATH + "device_id_cert.pem", "rb") as f:
            device_id_cert = f.read()
        with open(TEST_CERTS_PATH + "static_symm", "rb") as f:
            static_symm = f.read()
        with open(TEST_CERTS_PATH + "dev_uuid", "rb") as f:
            uuid = f.read()
    except Exception as e:
        print("Error opening certificate file: %s"
              % (str(e)))
        return None
    awdt_period_s = 1000
    name = "testdevice1"
    index = 1
    temperature = 26.5
    humidity = 0.89
    status = 2

    insert_device(db, uuid, name, device_id_cert, static_symm)

    update_alias_id_cert(db, uuid, alias_id_cert)
    update_device_id_cert(db, uuid, device_id_cert)
    update_awdt_period(db, uuid, awdt_period_s)
    update_data(db, uuid, status, index, temperature, humidity)

    name, awdt_period_s, status, index, temperature, humidity = get_device_info(db, uuid)
    print("%s = %s: period=%d, status=%d, index=%d, temp=%f, humidity=%f" %(uuid, name, awdt_period_s, status, index, temperature, humidity))

    device_id_cert, alias_id_cert = get_device_certs(db, uuid)
    print(device_id_cert)
    print(alias_id_cert)
    static_symm = get_static_symm(db, uuid)
    print("static symm = " + str(static_symm))
    # TODO handle hub stuff also in db (maybe in different db)
    # set_hub_certs(db, hub_cert, hub_sk, code_auth_cert, code_auth_sk)
    # hub_cert, hub_sk, code_auth_cert, code_auth_sk = get_hub_certs(db, uuid)

    # Get All Funktionen
    rows = get_device_info_all(db)
    for row in rows:
        (uuid, name, device_id_cert, alias_id_cert, awdt_period_s, status, index, temperature, humidity) = row
        print("%s = %s: " %(uuid, name), end='')
        if awdt_period_s:
            print("period=%d " %(awdt_period_s), end='' )
        if status:
            print("humidity=%d " %(status), end='' )
        if index:
            print("status=%d " %(status), end='' )
        if temperature:
            print("index=%d "  %(index), end='' )
        if humidity:
            print("humidity=%d " %(humidity), end='' )
        print("")

    close(db)