# password-manager-v1
A simple terminal based password manager written in python.

This password manager is based on a single script, but requires the following dependancies to function correctly:

- Python 3 or later
1. json
2. cryptography
3. operating system (os)
4. string
5. regex (re)
6. random
7. base64
8. pyperclip
9. system (sys)

To install missing dependancies with pip installed simply type:

pip install [dependancy] into the terminal

For operating systems other than linux, please change the first line to:

Mac: #! /usr/bin/env python3
Windows: #! python3

General Usage:

Usage: python3 PasswordManager.py [u/p/b/r/l/a] [account_name] [master_password]

u = username  p = password  b = both  r = remove  l = list accounts a = add
You do not need the [account_name] when listing accounts with [l]

For example: 'python3 PasswordManager.py p email supersafepass123' would return the password to the email account

'python3 PasswordManager.py a email supersafepass123' would create an email account

'python3 PasswordManager.py r email supersafepass123' would remove the email account if found

Note: always include the master password at the end of a command, if not the file will not be able to be decrypted and no operations can be performed
