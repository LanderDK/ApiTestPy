import datetime
import urllib.request
import wmi
import json
import os
import sys
import requests
import hashlib


class API:
    class Constants:
        # apiUrl = "https://api.blitzware.xyz/api/"
        apiUrl = "http://localhost:9000/api/"
        initialized = False
        started = False
        breached = False
        timeSent = datetime.datetime.now()

        @staticmethod
        def HWID():
            uuid = ""
            c = wmi.WMI()
            for item in c.Win32_ComputerSystemProduct():
                uuid = item.UUID
                break
            return uuid

        @staticmethod
        def IP():
            externalIpString = urllib.request.urlopen(
                "http://icanhazip.com").read().decode('utf8').strip()
            return externalIpString

    class ApplicationSettings:
        id = ""
        status = False
        hwidCheck = False
        developerMode = False
        programHash = ""
        version = ""
        downloadLink = ""
        freeMode = False

    class User:
        id = ""
        username = ""
        email = ""
        hwid = ""
        ip = ""
        expiry = ""
        lastLogin = ""
        authToken = ""

    class OnProgramStart:
        name = ""

        @staticmethod
        def Initialize(name, secret, version):
            API.OnProgramStart.Name = name
            try:
                API.Security.start()
                url = f"{API.Constants.apiUrl}applications/initialize"
                headers = {"Content-type": "application/json"}
                data = {"name": name, "secret": secret, "version": version}
                response = requests.post(
                    url, data=json.dumps(data), headers=headers)
                content = response.json()

                received_hash = response.headers.get('X-Response-Hash')
                recalculated_hash = API.Security.calculate_hash(response.text)

                # print(received_hash)
                # print(recalculated_hash)

                if API.Security.malicious_check(API.Constants.timeSent):
                    print("Possible malicious activity detected!")
                    sys.exit(0)

                if API.Constants.breached:
                    print("Possible malicious activity detected!")
                    sys.exit(0)

                if received_hash != recalculated_hash:
                    print("Possible malicious activity detected!")
                    sys.exit(0)

                if response.status_code == requests.codes.ok:
                    API.Constants.initialized = True
                    API.ApplicationSettings.id = content["id"]
                    API.ApplicationSettings.status = content["status"]
                    API.ApplicationSettings.hwidCheck = content["hwidCheck"]
                    API.ApplicationSettings.programHash = content["programHash"]
                    API.ApplicationSettings.version = content["version"]
                    API.ApplicationSettings.downloadLink = content["downloadLink"]
                    API.ApplicationSettings.developerMode = content["developerMode"]
                    API.ApplicationSettings.freeMode = content["freeMode"]

                    if API.ApplicationSettings.freeMode:
                        print("Application is in Free Mode!")

                    if API.ApplicationSettings.developerMode:
                        print(
                            "Application is in Developer Mode, bypassing integrity and update check!")

                        # Get the directory path of the current file
                        dir_path = os.path.dirname(os.path.abspath(__file__))
                        # Specify the file name
                        file_name = "main.py"
                        # Get the full file path and name
                        full_path = os.path.join(dir_path, file_name)

                        with open(f"{os.getcwd()}/integrity.log", "w") as f:
                            hash = API.Security.integrity(full_path)
                            f.write(hash)
                        print(
                            "Your application's hash has been saved to integrity.log, please refer to this when your application is ready for release!")
                    else:
                        if API.ApplicationSettings.version != version:
                            print(
                                f"Update {API.ApplicationSettings.version} available, redirecting to update!")
                            os.startfile(API.ApplicationSettings.downloadLink)
                            sys.exit(0)

                        if content["integrityCheck"] == True:
                            # Get the directory path of the current file
                            dir_path = os.path.dirname(
                                os.path.abspath(__file__))
                            # Specify the file name
                            file_name = "main.py"
                            # Get the full file path and name
                            full_path = os.path.join(dir_path, file_name)
                            if API.ApplicationSettings.programHash != API.Security.integrity(full_path):
                                print(
                                    "File has been tampered with, couldn't verify integrity!")
                                sys.exit(0)

                    if API.ApplicationSettings.status == False:
                        print(
                            "Looks like this application is disabled, please try again later!")
                        sys.exit(0)
                else:
                    if content["code"] == "UNAUTHORIZED":
                        print(content["message"])
                        sys.exit(0)
                    elif content["code"] == "NOT_FOUND":
                        print(content["message"])
                        sys.exit(0)
                    elif content["code"] == "VALIDATION_FAILED":
                        print(
                            f"Failed to initialize your application correctly in main.py!\n\nDetials:\n{content['details']}")
                        sys.exit(0)
                API.Security.end()
            except Exception as ex:
                if "Unable to connect to the remote server" in str(ex):
                    print("Unable to connect to the remote server!")
                    sys.exit(0)
                else:
                    print(str(ex))
                    sys.exit(0)

    @staticmethod
    def login(username, password):
        if not API.Constants.initialized:
            print("Please initialize your application first!")
            return False
        try:
            API.Security.start()
            API.Constants.timeSent = datetime.datetime.now()
            url = f"{API.Constants.apiUrl}users/login"
            headers = {"Content-type": "application/json"}
            data = {"username": username, "password": password,
                    "hwid": API.Constants.HWID(), "lastIP": API.Constants.IP(), "appId": API.ApplicationSettings.id}
            response = requests.post(
                url, data=json.dumps(data), headers=headers)
            content = response.json()

            received_hash = response.headers.get('X-Response-Hash')
            recalculated_hash = API.Security.calculate_hash(response.text)

            # print(received_hash)
            # print(recalculated_hash)

            if API.Security.malicious_check(API.Constants.timeSent):
                print("Possible malicious activity detected!")
                sys.exit(0)

            if API.Constants.breached:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if received_hash != recalculated_hash:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if response.status_code == requests.codes.ok or response.status_code == requests.codes.CREATED:
                API.User.id = content["user"]["id"]
                API.User.username = content["user"]["username"]
                API.User.email = content["user"]["email"]
                API.User.expiry = content["user"]["expiryDate"]
                API.User.lastLogin = content["user"]["lastLogin"]
                API.User.ip = content["user"]["lastIP"]
                API.User.hwid = content["user"]["hwid"]
                API.User.authToken = content["token"]
                API.Security.end()
                return True
            else:
                if content["code"] == "UNAUTHORIZED":
                    print(content["message"])
                elif content["code"] == "NOT_FOUND":
                    print(content["message"])
                elif content["code"] == "VALIDATION_FAILED":
                    print(content["details"])
                elif content["code"] == "FORBIDDEN":
                    print(content["message"])
                API.Security.end()
                return False
        except Exception as ex:
            if "Unable to connect to the remote server" in str(ex):
                print("Unable to connect to the remote server!")
            else:
                print(str(ex))
            API.Security.end()
            return False

    @staticmethod
    def register(username, password, email, license):
        if not API.Constants.initialized:
            print("Please initialize your application first!")
            return False
        try:
            API.Security.start()
            API.Constants.timeSent = datetime.datetime.now()
            url = f"{API.Constants.apiUrl}users/register"
            headers = {"Content-type": "application/json"}
            data = {"username": username, "password": password, "email": email, "license": license,
                    "hwid": API.Constants.HWID(), "lastIP": API.Constants.IP(), "id": API.ApplicationSettings.id}
            response = requests.post(
                url, data=json.dumps(data), headers=headers)
            content = response.json()

            received_hash = response.headers.get('X-Response-Hash')
            recalculated_hash = API.Security.calculate_hash(response.text)

            # print(received_hash)
            # print(recalculated_hash)

            if API.Security.malicious_check(API.Constants.timeSent):
                print("Possible malicious activity detected!")
                sys.exit(0)

            if API.Constants.breached:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if received_hash != recalculated_hash:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if response.status_code == requests.codes.ok or response.status_code == requests.codes.CREATED:
                API.User.id = content["user"]["id"]
                API.User.username = content["user"]["username"]
                API.User.email = content["user"]["email"]
                API.User.expiry = content["user"]["expiryDate"]
                API.User.lastLogin = content["user"]["lastLogin"]
                API.User.ip = content["user"]["lastIP"]
                API.User.hwid = content["user"]["hwid"]
                API.User.authToken = content["token"]
                API.Security.end()
                return True
            else:
                if content["code"] == "ER_DUP_ENTRY":
                    print("User with this username already exists!")
                elif content["code"] == "FORBIDDEN":
                    print(content["message"])
                elif content["code"] == "NOT_FOUND":
                    print(content["message"])
                elif content["code"] == "VALIDATION_FAILED":
                    print(content["details"])
                API.Security.end()
                return False
        except Exception as ex:
            if "Unable to connect to the remote server" in str(ex):
                print("Unable to connect to the remote server!")
            else:
                print(str(ex))
            API.Security.end()
            return False

    @staticmethod
    def extendSub(username, password, license):
        if not API.Constants.initialized:
            print("Please initialize your application first!")
            return False
        try:
            API.Security.start()
            API.Constants.timeSent = datetime.datetime.now()
            url = f"{API.Constants.apiUrl}users/upgrade"
            headers = {"Content-type": "application/json"}
            data = {"username": username, "password": password, "license": license,
                    "hwid": API.Constants.HWID(), "appId": API.ApplicationSettings.id}
            response = requests.put(
                url, data=json.dumps(data), headers=headers)
            content = response.json()

            received_hash = response.headers.get('X-Response-Hash')
            recalculated_hash = API.Security.calculate_hash(response.text)

            # print(received_hash)
            # print(recalculated_hash)

            if API.Security.malicious_check(API.Constants.timeSent):
                print("Possible malicious activity detected!")
                sys.exit(0)

            if API.Constants.breached:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if received_hash != recalculated_hash:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if response.status_code == requests.codes.ok or response.status_code == requests.codes.CREATED:
                API.User.id = content["user"]["id"]
                API.User.username = content["user"]["username"]
                API.User.email = content["user"]["email"]
                API.User.expiry = content["user"]["expiryDate"]
                API.User.lastLogin = content["user"]["lastLogin"]
                API.User.ip = content["user"]["lastIP"]
                API.User.hwid = content["user"]["hwid"]
                API.User.authToken = content["token"]
                API.Security.end()
                return True
            else:
                if content["code"] == "UNAUTHORIZED":
                    print(content["message"])
                elif content["code"] == "NOT_FOUND":
                    print(content["message"])
                elif content["code"] == "VALIDATION_FAILED":
                    print(content["details"])
                elif content["code"] == "FORBIDDEN":
                    print(content["message"])
                API.Security.end()
                return False
        except Exception as ex:
            if "Unable to connect to the remote server" in str(ex):
                print("Unable to connect to the remote server!")
            else:
                print(str(ex))
            API.Security.end()
            return False

    @staticmethod
    def log(username, action):
        if not API.Constants.initialized:
            print("Please initialize your application first!")
            sys.exit(0)
        try:
            API.Security.start()
            API.Constants.timeSent = datetime.datetime.now()
            url = f"{API.Constants.apiUrl}appLogs/"
            headers = {"Content-type": "application/json"}
            data = {"username": username, "action": action,
                    "ip": API.Constants.IP(), "appId": API.ApplicationSettings.id}
            response = requests.post(
                url, data=json.dumps(data), headers=headers)
            content = response.json()

            if API.Security.malicious_check(API.Constants.timeSent):
                print("Possible malicious activity detected!")
                sys.exit(0)

            if API.Constants.breached:
                print("Possible malicious activity detected!")
                sys.exit(0)

            if response.status_code == requests.codes.ok or response.status_code == requests.codes.CREATED:
                API.Security.end()
            else:
                if content["code"] == "UNAUTHORIZED":
                    print(content["message"])
                elif content["code"] == "NOT_FOUND":
                    print(content["message"])
                elif content["code"] == "VALIDATION_FAILED":
                    print(content["details"])
                API.Security.end()
                sys.exit(0)
        except Exception as ex:
            if "Unable to connect to the remote server" in str(ex):
                print("Unable to connect to the remote server!")
            else:
                print(str(ex))
            API.Security.end()
            sys.exit(0)

    class Security:
        @staticmethod
        def start():
            drive = os.path.splitdrive(os.environ['systemroot'])[0]
            if API.Constants.started:
                print("A session has already been started, please end the previous one!")
                sys.exit(0)
            else:
                with open(f"{drive}\\Windows\\System32\\drivers\\etc\\hosts", "r") as f:
                    contents = f.read()
                    if "api.blitzware.xyz" in contents:
                        API.Constants.breached = True
                        print("DNS redirecting has been detected!")
                        sys.exit(0)
                API.Constants.started = True

        @staticmethod
        def end():
            if not API.Constants.started:
                print("No session has been started, closing for security reasons!")
                sys.exit(0)
            else:
                API.Constants.started = False

        @staticmethod
        def integrity(filename):
            result = None
            with open(filename, "rb") as f:
                md5 = hashlib.md5()
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    md5.update(data)
                result = md5.hexdigest()
            return result

        @staticmethod
        def malicious_check(date):
            dt1 = date  # time sent
            dt2 = datetime.datetime.now()  # time received
            d3 = dt2 - dt1
            if abs(d3.seconds) >= 5:
                API.Constants.breached = True
                return True
            else:
                return False

        @staticmethod
        def calculate_hash(data):
            hash_object = hashlib.sha256(data.encode())
            return hash_object.hexdigest()
