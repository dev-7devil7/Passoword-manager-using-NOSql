# For mails
import smtplib
from email.message import EmailMessage
#for database connection
import pymongo
from pymongo import MongoClient
import re
from datetime import datetime
from random import *

#Connection to the database
connection = MongoClient()

#creating a datbase
main_db = connection["Password_manager"]

# For maintaining log details
current = str(datetime.today()).split()
date = current[0]
time = current[-1].split(".")[0]

# To send otp and validate otp
def validate(sen_otp):
    rec_otp = input("Enter 6 digit otp: ").strip()
    return (len(rec_otp) == 6 and rec_otp == sen_otp)
def send_otp(rec):
    # Regular expression for gmail validation
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(regex, rec):
        try:
            #Create your SMTP session
            server = smtplib.SMTP('smtp.gmail.com', 587)

            #Use TLS to add security
            server.starttls()
            otp = randint(100000,999999)
            otp = str(otp)

            #User Authentication
            server.login("pwdmanager2022@gmail.com","I love devil@7,")

            #Defining The Message
            message = """Hey user!!!
            Welcome to password manager
            your 6 digit otp is {}""".format(otp)

            #Sending the Email
            email = EmailMessage()
            email["From"] = "pwdmanager2022@gmail.com"
            email["To"] = rec
            email["Subject"] = "Create Account"
            email.set_content(message)
            server.send_message(email)

            #Terminating the session
            server.quit()

            print("OTP sent succesfully check your mail")
            return validate(otp)
        except Exception as ex:
            print("Something went wrong please try again")
            return False
    else:
        print("Please enter valid email and try again")
        return False

# Password validation
def password_validation():
    print("Create your master password which should be as follows")
    #Rules for password
    print("1. Should be of length 6 - 20")
    print("2. Should have atleast one lowe and upper case letter")
    print("3. Atleast one digit")
    print("4. Atleast one sepcial symbol[$@#,.%&]")
    print()

    special = ['$', '@', '#', '%',",",".","&"]
    flag = True
    password = input("Enter your password: ")

    #Validating password
    if len(password) < 6 and len(password) > 20:
        flag = False
        print("Lenght of password should be 6 to 20")
    if not any(char.isdigit() for char in password):
        flag = False
        print("Password should have atleast one integer")
    if not any(char.islower() for char in password):
        flag = False
        print("Password should have atleast one lowercase letter")
    if not any(char.isupper() for char in password):
        flag = False
        print("Password should have atleast one uppercase letter")
    if not any(char in special for char in password):
        flag = False
        print("Password should have atleast one special character")
    if flag:
        return password
    else:
        return flag

def sign_up():
    def add_account(email):
        #Creating an collection object to add user details
        user_data_collection = main_db["users"]
        user_name = input("Enter user name: ")

        #user list
        user_list = [i['uname'] for i in user_data_collection.find()]

        #Make sure username is not previously existed in the database
        if any([user_name.lower() == i.lower() for i in user_list]):
            print("UserName exists. Try with other name")
            return

        #Getting secure password
        password = password_validation()
        if password:
            entry = {"email":email, "uname":user_name, "password":password,"date":date,"time":time}
            try:
                user_data_collection.insert_one(entry)
                print("Account added succesfully :):):)")
            except:
                print("Something went wrong in data entry. Please try again later")
        else:
            print("Your password is not secure. Try with a secure one")

    def create_account(email_id):
        #Validate OTP
        if send_otp(email_id):
            print("OTP validated succesfully")
            print()
            add_account(email_id)
        else:
            print("Invalid OTP please try again")


    print("----------------CREATE    YOUR    ACCOUNT------------------\n\n")
    email_id = input("Enter email: ").strip()
    create_account(email_id)

#Signin
def sign_in():
    def add(user_db):
        #instance for storing passwords
        user_instance = main_db["Passwords"]

        #passwords collection
        password_collection = user_instance[user_db]
        print("\nHey user please provide domain, username and password")
        print("Example domain:facebook\nusername:user1\npassword:password123")
        print()

        #reading data to add
        domain = input("Enter domain: ")
        user_name = input("Enter username: ")
        password = input("Enter password: ")

        #Creating a dictionry or JSON
        record = {'domain':domain,'user_name':user_name,'password':password}

        if password_collection.insert_one(record):
            print("Status = Success")
        else:
            print("Status = Fail\nPlease try again")
        return

    def read(user_db):

        #Creating an instance for accesing user data
        user_instance = main_db["Passwords."+user_db]
        print("\nHey user please provide domain, username and passpord")
        print("Example domain:facebook\nusername:user1\n")
        print()

        #Reading required details
        domain = input("Enter domain: ")
        user_name = input("Enter username: ")

        #JSON object
        record = {'domain':domain, 'user_name':user_name}

        my_doc = [1 for i in user_instance.find(record)]
        if len(my_doc) == 0:
            print("\nInvalid domain or username\nPlease try again\n\n")
            return
        else:
            for i in user_instance.find(record):
                print("Username:",i['user_name'],"Password:",i['password'])
            return

    #To show all the data in the user database
    def show_all(u_name):

        #Confirming user
        print("Please confirm your account\n\n")
        email = input("Enter email: ")
        email_instance = main_db['users']
        search = {'email':email,'uname':uname}
        emails_list = [1 for i in email_instance.find(search)]

        if len(emails_list) != 0:
            if send_otp(email):
                print("\n\nDomain\t\tUserName\tPassword")
                print("------\t\t--------\t--------\n")
                total_list = main_db["Passwords."+u_name]
                for i in total_list.find():
                    print(i['domain'],i['user_name'],i['password'],sep = "\t\t")
            else:
                print("Do not fool me!!! ")
        else:
            print("We cannot find your account. Please try again")

    #For updating any user passwords
    def update_password(db):
        user_instance = main_db["Passwords."+db]
        old = {'domain': input("Enter domain: "),
                 'user_name': input("Enter username: "),
                'password':input("Enter password: ")}
        update_list = [1 for i in user_instance.find(old)]
        if len(update_list) != 0:
            new = {"$set": {'password': input("Enter new password")}}
            try:
                user_instance.update_one(old,new)
                print("Updated succesfully :):)")
            except:
                print("Something went wrong please try again")
        else:
            print("Please be sure that you have given valid details\n")


    print("-----------------Please enter valid user name and password------------------------")

    #Validating user
    user_data_collection = main_db["users"]
    uname = input("Enter username: ")
    password = input("Enter password: ")
    myquery = {'uname':uname, 'password':password}
    my_doc = [1 for i in user_data_collection.find(myquery)]

    #If user is not valid
    if len(my_doc) == 0:
        print("Invalid username or password")
        return
    else:
        while(True):
            print("1.Add\n2.Read\n3.Show all\n4.Update password")
            choice = input("Enter your choice: ")
            if choice == '1':
                add(uname)
            elif choice == '2':
                read(uname)
            elif choice == '3':
                show_all(uname)
            elif choice == '4':
                update_password(uname)
            else:
                print("Invalid choice")
            quit = input("Press enter to quit")
            if quit == "":
                break
        return

# Incase if the user forgotten his master password
def forgot_password():
    user_data = main_db["users"]
    user_name = input("Enter username: ")
    query = {'uname':user_name}
    try:
        user_dict = [i for i in user_data.find(query)][0]
    except:
        print("Invalid access")
        return
    if user_name == user_dict['uname']:
        email = input("Enter email: ")
        if email == user_dict['email']:
            if send_otp(email):
                new_pass = password_validation()
                if new_pass:
                    new_dict = {'email':email,"uname":user_name,"password":new_pass,'date':date,"time":time}
                    try:
                        user_data.delete_many(user_dict)
                        user_data.insert_one(new_dict)
                        print("Password updated succesfully")
                    except:
                        print("Password is not updated. sorry")
                else:
                    print("Please try with a secure password")
            else:
                print("Invalid OTP please try again")
        else:
            print("Invalid email")
    else:
        print("Invalid user")

#Generating a password
def generate_password():
    pa = ""
    lower = [chr(i) for i in range(ord('a'), ord('z')+1)]
    upper = [chr(i) for i in range(ord('A'), ord("Z")+1)]
    digits = [str(i) for i in range(10)]
    special_characters = [i for i in "!#$%*( :\)[]{}|,.?/@+-="]
    combined = lower + upper + digits + special_characters
    shuffle(combined)
    #pa = choice(upper) + choice(lower) + choice(digits) + choice(special_characters)
    for i in range(16):
        pa += combined[randint(0,84)]
    return pa

# main
if __name__ == '__main__':
    greet = "Welcome to password manager\nMy job is to keep your passwords safe and secure :):)"
    print(greet)
    print()
    print("1.Sign up\n2.Sign in\n3.orgot password\n4.Generate password\n")
    print()
    choice = int(input("Enter your choice:"))
    print()
    if choice == 1:
        sign_up()
    elif choice == 2:
        sign_in()
    elif choice == 3:
        forgot_password()
    elif choice == 4:
        print("Suggested password is:",generate_password())
    else:
        print("Invalid choice. Please pick the right option")
