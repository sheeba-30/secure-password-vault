import base64
import getpass
import json
import os
import secrets
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PATH = "vault.enc"


def cipher_for(salt):
    password = getpass.getpass("Master password: ").encode()
    if not password:
        raise SystemExit("Master password cannot be empty.")
    key = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=600_000).derive(password)
    return Fernet(base64.urlsafe_b64encode(key))


def load():
    if not os.path.exists(PATH):
        salt = secrets.token_bytes(16)
        return {}, salt, True, cipher_for(salt)
    with open(PATH, "rb") as file:
        salt, token = file.read(16), file.read()
    try:
        cipher = cipher_for(salt)
        return json.loads(cipher.decrypt(token)), salt, False, cipher
    except Exception as exc:
        raise SystemExit("Could not decrypt vault; check the master password or restore a backup.") from exc


def save(data, salt, is_new, cipher):
    with open(PATH, "wb") as file:
        file.write(salt + cipher.encrypt(json.dumps(data).encode()))
    os.chmod(PATH, 0o600)
    if is_new:
        print("Created encrypted vault. Keep the master password and a secure backup safe.")


if len(sys.argv) != 2 or sys.argv[1] not in {"add", "get", "list"}:
    raise SystemExit("Usage: python vault.py add|get|list")

entries, salt, is_new, cipher = load()
command = sys.argv[1]
if command == "add":
    name = input("Account name: ").strip()
    if not name:
        raise SystemExit("Account name cannot be empty.")
    entries[name] = {"username": input("Username: ").strip(), "password": getpass.getpass("Account password: ")}
    save(entries, salt, is_new, cipher)
elif command == "get":
    name = input("Account name: ").strip()
    item = entries.get(name)
    print(json.dumps(item, indent=2) if item else "No matching account.")
else:
    for name in sorted(entries):
        print(name)
