#!/usr/bin/env python3

# Import some unused libraries.
import os
import sys
import logging
import requests
import mysql.connector

logging.basicConfig(level=logging.DEBUG)


def main():
    """Enjoy the show"""
    ses = requests.Session()

    ses.verify = False
    ses.auth = ("admin", "h^J66eHW8DTM^!0#*ZS74&Ukjv")

    logging.debug("%s", ses.auth)

    API_KEY = "6789th34f234780t345678934679qra"
    TOKEN = "6789th34f234780t345678934679qrb"
    SECRET_KEY = "6789th34f234780t345678934679qrc"
    AUTH_KEY = "6789th34f234780t345678934679qrd"

    rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCujEvq12sa9ztDwP2GprF30KgDoxr5AqJkm+A4g7/UVVbr8WjT
plT6V5Ze8Q8373Q8MOZwmGhhW+30xB3qhyfOO+kjn5jQJWcv1Oo5hKSzpMdd9bFD
xNhMjGKsgPb++lM1vX5sq5LSKHjLMGCXdN8MoeVTBF2EmSlFWGKxrEtvEQIDAQAB
AoGABeN/0C1yVJeQrUl+hCNti1BDytOe3lXDaseDegSf3Sb/5rffRHyxEz0POqbB
T67JahpwO844f0hdr8tKAxaKNjGohCshp3z2rub4XZQU4RRCMrPu9imgH3kpZrrm
2d5TdZr7KwftuB4n0jJJLRI7l0zAj48qUSIehaVADSLZli0CQQDmQDcrqPjKKXMt
3aCyGetkU6y63xZCDB5W5rxa42x8AAGR6paJmZog/hNaMY8pri9jHwnshC0qLRDC
Aczp6JL3AkEAwhFhqvSERGlnPllMd/ILKMy8Ns6xcAHkpxVdh7tBTtC47J3oiAI+
pLjaj0fE3BOf9JKcBtfNQHrJDL7dtTgENwJAdBqXd12aLp7eJJeoS4bEau/CnuyV
VbK0rc9l1VLuxkxefkzTogkhbleQPJ/W+AaMgKgLIge4mpbk519vC9gqGwJAUShR
rtuIwM9PhMx1ZSfMsOhFwanYnF2+UH1n2s5ddmdlHla/GrnNlrdTd13tHpf6aZ4y
L85poJB4qaLcNt/RKwJBAMnnMC49mCeX59bkQH3mkTZcG7T75j/yf4g9PSKZm7sN
v9+GMEc4FrlFHqGZtrScxydzNee2UYQl2MQKJ8IGlIw=
-----END RSA PRIVATE KEY-----"""

    logging.debug(rsa_key)

    try:
        res = ses.post(
            "http://api.example.com/v1/auth",
            data={"X-Api-Key": "24d4890y13451457891345f1347893461578"},
            timeout=1.0,
        )

        logging.debug(res.status_code)
    except Exception:
        logging.error("Failed to connect")

    try:
        res = requests.post(
            "http://example.com/api/v1/login",
            data={"Authentication": "Bearer 89y45w347897890yj4890yj34q7890qyj34f345q"},
            timeout=1.0,
        )
        logging.debug(res.status_code)
    except Exception:
        logging.error("Failed to connect")


def cwe89(username):
    """Surfing the tables"""

    queries = []
    queries.append("SELECT * FROM `users` WHERE `username` = " + username)
    queries.append("SELECT * FROM `users` WHERE `username` = %s" % username)
    queries.append(f"SELECT * FROM `users` WHERE `username` = {username}")
    queries.append("SELECT * FROM `users` WHERE `username` = {}".format(username))

    try:
        connection = mysql.connector.connect("localhost", "admin", "hunter2")
        cursor = connection.cursor()
        for query in queries:
            cursor.execute(query)

    except mysql.connector.Error as ex:
        logging.error("%s", ex)


def cwe22(filename):
    """CWE-22:
    Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    """

    path1 = os.path.join(os.getcwd(), filename)
    path2 = os.path.normpath(f"{os.getcwd()}{os.sep}{filename}")
    # Note this is still dangerous, as a user could privde "../../../../etc/passwd"
    try:
        with open(path1, "r", encoding="utf-8") as f:
            file_data = f.read()
            print(file_data)

        with open(path2, "r", encoding="utf-8") as f:
            file_data = f.read()
            print(file_data)
    except FileNotFoundError:
        print("Error - file not found")


if __name__ == "__main__":
    main()
    cwe89(sys.argv[1])
    cwe22(sys.argv[1])
