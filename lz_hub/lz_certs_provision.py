#!/bin/bash

import lz_hub_db

def main():
    print("Loading hub certificate and key")
    try:
        with open("certificates/hub_cert.pem", "r") as f:
            hub_cert = f.read()
    except Exception as e:
        print("Error: Unable to open hub cert file: %s. Exit.." %(str(e)))
        return -1
    try:
        with open("certificates/hub_sk.pem", "r") as f:
            hub_sk = f.read()
    except Exception as e:
        print("Error: Unable to open hub key file: %s. Exit.." %(str(e)))
        return -1

    print("Loading code auth certificate and key")
    try:
        with open("certificates/code_auth_cert.pem", "r") as f:
            code_auth_cert = f.read()
    except Exception as e:
        print("Error: Unable to open hub cert file: %s. Exit.." %(str(e)))
        return -1
    try:
        with open("certificates/code_auth_sk.pem", "r") as f:
            code_auth_sk = f.read()
    except Exception as e:
        print("Error: Unable to open hub key file: %s. Exit.." %(str(e)))
        return -1

    db = lz_hub_db.connect()
    if not db:
        print("Error: failed to connect to database")
        return -1

    print("Updating database")

    if not lz_hub_db.update_hub_cert(db, "hub_cert", hub_cert, hub_sk):
        print("Error: failed to update hub cert")

    if not lz_hub_db.update_hub_cert(db, "code_auth_cert", code_auth_cert, code_auth_sk):
        print("Error: failed to update hub cert")

    print("Finished")

### main ###
if __name__ == "__main__":
    main()