# Secure Password Vault

A local command-line password vault. It derives an encryption key from the master password with PBKDF2 and protects the JSON vault with Fernet authenticated encryption.

## Run

Install `requirements.txt`, then use `python vault.py add`, `python vault.py get`, or `python vault.py list`. The encrypted vault is saved in the current directory. Back it up securely.

This learning project has not undergone a security audit. Use a reputable password manager for real accounts.

## Stack

Python, cryptography, PBKDF2, Fernet
