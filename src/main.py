from API import API
import sys

API.OnProgramStart.Initialize(
    "BlitzWare", "64aa5135948a28fa6040b0d6900de77e9a3924e6cee6cc3333c32ff5f8707e8e", "1.0")

print("\n[1] Login")
print("[2] Register")
if not API.ApplicationSettings.freeMode:
    print("[3] Extend Subscription")
print("\nOption:")
option = input()

if option == "1":
    print("\nUsername:")
    username = input()
    print("Password:")
    password = input()

    if API.login(username=username, password=password):
        print("Successfully Logged In!")
        print("ID:", API.User.id)
        print("Username:", API.User.username)
        print("Email:", API.User.email)
        print("Subscription Expiry:", API.User.expiry)
        print("HWID:", API.User.hwid)
        print("Last Login:", API.User.lastLogin)
        print("IP:", API.User.ip)
        input()
        # Do code you want
    else:
        sys.exit(0)
elif option == "2":
    print("\nUsername:")
    username = input()
    print("Password:")
    password = input()
    print("Email:")
    email = input()
    license = "N/A"
    if not API.ApplicationSettings.freeMode:
        print("License:")
        license = input()
    
    if API.register(username=username, password=password, email=email, license=license):
        print("Successfully Registered!")
        input()
    else:
        sys.exit(0)

if not API.ApplicationSettings.freeMode:
    if option == "3":
        print("\nUsername:")
        username = input()
        print("Password:")
        password = input()
        print("License:")
        license = input()

        if API.extendSub(username=username, password=password, license=license):
            print("Successfully Extended Your Subscription!")
            input()
        else:
            sys.exit(0)
