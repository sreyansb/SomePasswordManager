from msilib.schema import Error
import os.path
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import argparse
import config_file
import json
import hashlib

class Singleton_Fernet:
    __instance = None
    def __init__(self):
        filekey = ""
        with open(config_file.key_file,"rb") as file:
            filekey = file.read()
        Singleton_Fernet.__instance = Fernet(filekey)
    def instance(self):
        if not(Singleton_Fernet.__instance):
            Singleton_Fernet()
        return Singleton_Fernet.__instance

def generate_parser():
    parser = argparse.ArgumentParser(description= "-r for read, -w for write, -i for initialize")
    parser.add_argument("-r","--read",help = "read password")
    parser.add_argument("-w","--write",help = "write passwords")
    parser.add_argument("-i","--initialize",help = "initialize manager")
    return parser

def is_zeroth_line_same(zeroth_line,singleton_fernet: Singleton_Fernet):
    with open(config_file.password_file,"rb") as file:
        zero_line = file.readline()
    decrypted_zero_line = singleton_fernet.instance().decrypt(zero_line)
    #can't compare bytes to bytes
    return decrypted_zero_line.decode() == zeroth_line.decode()

def read():
    required_use_case = input("Enter the use-case : ").lower()
    s = Singleton_Fernet()
    if required_use_case != "all":
        with open(config_file.password_file,"rb") as file:
            try:
                while(file):
                    use_case = s.instance().decrypt(file.readline()).decode().split("\t")
                    if use_case[0] == required_use_case:
                        use_case = {"USE_CASE":use_case[0],"USERNAME":use_case[1],"PASSWORD":use_case[2]}
                        print(use_case)
                        break
            except InvalidToken as E:
                return
    else:
        use_cases = []
        with open(config_file.password_file,"rb") as file:
                while(file):
                    try:
                        use_cases.append(s.instance().decrypt(file.readline()).decode().split("\t"))
                    except InvalidToken as E:
                        break
        result = []
        heading = ["USE_CASE","USERNAME","PASSWORD"]
        for use_case in use_cases[1:]:
            result.append({heading[index]:use_case[index] for index in range(3)})
        print(json.dumps(result))

def write():    
    use_case = input("Enter the use-case : ")
    user_id = input("Enter the user-id : ")
    use_case_password = input("Enter the password of the application : ")
    line = f"{use_case.lower()}\t{user_id}\t{use_case_password}"
    s = Singleton_Fernet()
    with open(config_file.password_file,"ab") as file:
        file.write(s.instance().encrypt(line.encode()))
        file.write("\n".encode())


def initialize(password):
    if os.path.isfile(config_file.password_file):
        regen = input("A password file already exists. Press Y if you want to rewrite : ")
        if regen.upper() != "Y":
            return

    key = Fernet.generate_key()
    fernet = Fernet(key)
    with open(config_file.key_file,"wb") as file:
        file.write(key)
    zeroth_line = f"{password}{config_file.zeroth_line}"
    
    with open(config_file.password_file,"wb") as file:
        #print(zeroth_line)
        file.write(fernet.encrypt(zeroth_line.encode()))
        file.write("\n".encode())

def main():
    parser = generate_parser()
    args = parser.parse_args()
    if not(args.read or args.write or args.initialize):
        return
    password = args.read or args.write or args.initialize
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if args.initialize:
        initialize(hashed_password)
        return
    if not(os.path.isfile(config_file.password_file)):
        print("Manager not initialized")
        return
    s = Singleton_Fernet()
    zeroth_line = hashed_password+config_file.zeroth_line
    if not(is_zeroth_line_same(zeroth_line.encode(),s)):
        print("Given Password doesn't match manager's password")
        return
    if args.read:
        read()
        return
    if args.write:
        write()
        return

if __name__ == "__main__":
    main()
