#! /usr/bin/python3

# Other operating systems:

# For Mac: #! /usr/bin/env python3
# For Windows: #! python3

# Usage: python PasswordManager.py [u/p/b/r/l/a] [account_name] [master_password]
# u = username  p = password  b = both  r = remove  l = list accounts a = add
# You do not need the [account_name] when listing accounts with [l]

# For example: 'python PasswordManager.py p email supersafepass123' would return the password to the email account


import base64, sys, pyperclip, os, re, json, random, string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

accounts_file_path = ''
encrypted = False
salt = 0

def fileloader():
    loop = True
    global accounts_file_path
    try:
        accounts_file = open(accounts_file_path)
    except:
        print("Sorry! the accounts master file could not be loaded\n"+\
            "Would you like to create one? (Y/N)")
        while loop == True:
            answer = input()
            if answer == "Y" or answer == "y":
                script_path = os.path.abspath(__file__)
                print("Please type the full path for where you would want the file to be located:")
                try:
                    path = os.path.abspath(input())
                except:
                    print("Whoops, invalid path. please try again")
                    sys.exit()
                default_path_changer(script_path,path)
                f = open(path+"/accounts_database.txt","w")
                f.close()
                print("Master file path set!\n")
                accounts_file = open(accounts_file_path)
                loop = False
            elif answer == "N" or answer == "n":
                print("OK! Closing Program...")
                loop = False
                sys.exit()
            else:
                print("That is not a valid option, please try again:")

    accounts = accounts_file.read()
    accounts_file.close()


    return accounts



def default_path_changer(path,userinput):
    counter = 0
    output = ''
    f = open(path,"r")
    file_data = f.readlines()
    f.close()
    for line in file_data:
        if re.search("accounts_file_path", line) and counter < 1:
            counter += 1
            line = "accounts_file_path = " + "'" + str(userinput) +'/accounts_database.txt'+ "'" + '\n'
        else:
            line = line
        output += line
    f = open(path,"w")
    f.write(output)
    f.close()

def encrypted_status_changer(path,status):
    counter = 0
    output = ''
    f = open(path,"r")
    file_data = f.readlines()
    f.close()
    for line in file_data:
        if re.search("encrypted", line) and counter < 1:
            counter += 1
            line = "encrypted = " + str(status) + '\n'
        else:
            line = line
        output += line

    f = open(path,"w")
    f.write(output)
    f.close()

def salt_changer(salt, path):
    counter = 0
    output = ''
    f = open(path,"r")
    file_data = f.readlines()
    f.close()
    for line in file_data:
        if re.search("salt", line) and counter < 1:
            counter += 1
            line = "salt = " + str(salt) + '\n'
        else:
            line = line
        output += line
    f = open(path,"w")
    f.write(output)
    f.close()


def account_checker(account, _input, key, _key):

    global accounts_file_path
    global encrypted

    try:
        if encrypted == True:

            f = open(accounts_file_path, "r")
            data = f.read()
            f.close()

            try:
                decrypted_data = decrypt_file_data(_key,data)
            except SystemExit:
                sys.exit()

        else:
            encrypt_file(_key, accounts_file_path, _input)

            f = open(accounts_file_path, "r")
            data = f.read()
            f.close()

            try:
                decrypted_data = decrypt_file_data(_key,data)
            except SystemExit:
                sys.exit()

            script_path = os.path.abspath(__file__)
            encrypted_status_changer(script_path, True)

        accounts = json.loads(decrypted_data)

    except SystemExit:
        sys.exit()

    except:
        accounts = ''

    if account in accounts:

        if key == "a":
            print("Account already created! To remove it, use key [r] ")
            sys.exit()

        print(account + " detected")
        if key == "r":
            remove_account(account, accounts, _key)
            sys.exit()

        elif key == "u":
            pyperclip.copy(accounts[account]["username"])

        elif key == "p":
            pyperclip.copy(accounts[account]["password"])

        elif key == "b":
            pyperclip.copy(accounts[account]["username"] + "   " + accounts[account]["password"])

        print("The contents has been copied to your clipboard")

    elif key == "a":

        print("This account was not found, would you like to create it? (Y/N)")
        answer = input()

        if answer == "Y" or answer == "y":

            print("Username:")
            username = input()
            print("Would you like an randomly generated password? (Y/N)")
            answer = input()

            if answer == "Y" or answer == "y":
                password = random_password()

            else:
                print("Password:")
                password = input()

            create_entry(account,username,password, accounts, _key)
            print("Entry added!")

        else:
            sys.exit()
    else:
        print('''
Account not found! You can add an account entry with [a] before the account name.
For example: python3 [a] [account_name] [master_password]
''')
        sys.exit()



def create_entry(_account,username,password,_data,_key):

    global accounts_file_path

    account = {}
    account.update(_data)
    login = {
        "username": username,
        "password": password
    }
    account[_account] = login
    account_data = json.dumps(account)

    encrypt_file(_key,accounts_file_path,account_data)





def random_password():
    password_length = 20
    password = ''
    possible_characters = string.ascii_letters + string.digits #+ string.punctuation

    for i in range(password_length):
        password += random.choice(possible_characters)

    return password




def remove_account(account, accounts, key):

    if account in accounts:
        global accounts_file_path
        del accounts[account]
        data = json.dumps(accounts, indent = 4)
        encrypt_file(key,accounts_file_path,data)
        print(account + " deleted")



def list_accounts(accounts):
    _list = ""

    for entry in accounts.keys():
        _list += (entry+" ")
    print(_list)
    sys.exit()



def usage():
    print('''
Usage: python PasswordManager.py [u/p/b/r/l/a] [account_name] [master_password]
u = username  p = password  b = both  r = remove  l = list accounts a = add
You do not need the [account_name] when listing accounts with [l]

For example: 'python PasswordManager.py p email supersafepass123' would return the password to the email account''')


def get_key(_password):
    # try:
    #     key_f = open("key.key", "rb")
    #     key = key_f.read()
    #     return key

    # except:
    #     key = bytes(Fernet.generate_key())
    #     key_f = open("key.key", "wb")
    #     key_f.write(key)
    #     key_f.close()
    #     return key

    global salt

    if salt == 0:
        salt = os.urandom(16)

    else:
        salt = salt

    own_file_path = os.path.abspath(__file__)
    salt_changer(salt,own_file_path)

    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=390000,
    )

    password = bytes(_password, "utf8")
    key = base64.urlsafe_b64encode(kdf.derive(password))

    return [key, salt]


# def encrypt_file(_key, _path):
#     f_to_encrypt = open(_path, "rb")
#     file_data = f_to_encrypt.read()
#     f_to_encrypt.close()

#     f = Fernet(_key)
#     encrypted_data = f.encrypt(file_data)

#     f_to_encrypt = open(_path, "wb")
#     f_to_encrypt.write(encrypted_data)
#     f_to_encrypt.close


def encrypt_file(_key, _path, data):

    file_data = bytes(data,"utf8")
    f = Fernet(_key[0])

    encrypted_data = f.encrypt(file_data)

    f_to_encrypt = open(_path, "wb")
    f_to_encrypt.write(encrypted_data)
    f_to_encrypt.close()


# def decrypt_file_data(_key, _path):
#     f_to_decrypt = open(_path, "rb")
#     file_data = f_to_decrypt.read()
#     f_to_decrypt.close()

#     f = Fernet(_key)
#     decrypted_data = f.decrypt(file_data)

#     return decrypted_data


def decrypt_file_data(_key, _data):

    try:

        data = bytes(_data,"utf8")
        f = Fernet(_key[0])
        decrypted_data = f.decrypt(data)
        return decrypted_data

    except:
        print("Could not decrypt")
        usage()
        sys.exit()


def main():

    if len(sys.argv) < 2:
        usage()
        sys.exit()

    if len(sys.argv) > 4:
        usage()
        sys.exit()

    accounts = fileloader()

    key = sys.argv[1]

    if key == "l":
        if len(sys.argv) < 3:
            print("Please include the master password!!")
            sys.exit()

        _password = sys.argv[2]
        _key = get_key(_password)
        
        try:
            data = decrypt_file_data(_key, accounts)
        except SystemExit:
            sys.exit()

        if data != None or data != "":
            list_accounts(json.loads(data))

        else:
            print('')

    else:

        if len(sys.argv) < 4:
            print("Please include the master password!!")
            sys.exit()

        account = sys.argv[2] # account name is the second first thing called after the script
        _password = sys.argv[3]
        _key = get_key(_password)

    account_checker(account, accounts, key, _key)



main()

# key = get_key()
# f = open(accounts_file_path)
# data = f.read()
# f.close()
# print(decrypt_file_data(key, data))
