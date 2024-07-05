from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, Blueprint
from dotenv import load_dotenv
import os
from functools import wraps
from datetime import datetime, timedelta, timezone
from Modules import AES256, SHA256, Mail
import re
import secrets
import string
from db import mongo

StaffsBP = Blueprint('staffs', __name__)

def LoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'UserName' in session: # and session['Role'] == "Staff":
            session_key = session['SessionKey']
            user_name = session['UserName']
            user_session = mongo.db.UserSessions.find_one({
                'SessionKey': session_key,
                'UserName': user_name,
                'ExpirationTime': {'$gt': datetime.now(timezone.utc)}
            })
            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('staffs.Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('staffs.Login'))
    return decorated_function

def NotLoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'UserName' in session:
            return redirect(url_for('staffs.Index'))
        return view_func(*args, **kwargs)
    return decorated_function

def GenerateSessionKey(length=32):
    SessionKey = secrets.token_hex(length // 2)
    return SessionKey

def GenerateVerificationCode(length=32):
    characters = string.ascii_letters + string.digits
    VerificationCode = ''.join(secrets.choice(characters) for _ in range(length))
    return VerificationCode

def SendVerificationEmail(UserName, email, VerificationCode):
    subject = "SKCET - Verify your Account"
    body = "Verification Code: " + str(VerificationCode)
    if Mail.SendMail(subject, body, email):
        mongo.db.StaffVerification.insert_one({'UserName': UserName, 'VerificationCode': VerificationCode, 'Verified': False})

def IsUserVerified(UserName):
    VerifiedStatus = mongo.db.StaffVerification.find_one({'UserName': UserName, 'Verified': True})
    return VerifiedStatus is not None

def PasswordResetMail(UserName, email, ResetKey):
    subject = "SKCET - Password Reset"
    link = "http://localhost:5000/resetkey/" + str(ResetKey)
    body = "Password Reset Code: " + str(ResetKey) + f" {link}"
    if Mail.SendMail(subject, body, email):
        currenttime = datetime.utcnow()
        mongo.db.PasswordReset.insert_one({'UserName': UserName, 'ResetKey': ResetKey, 'CreatedAt': currenttime, 'ExpirationTime': currenttime + timedelta(hours=6)})
        mongo.db.PasswordReset.create_index('ExpirationTime', expireAfterSeconds=0)

@StaffsBP.route('/')
def Index():
    return render_template("Index.html")

# @StaffsBP.route('/register', methods=['GET', 'POST'])
# @NotLoggedInUser
# def Registration():
#     if request.method == 'POST':
#         name =  request.form['name']
#         email =  request.form['email']
#         password = request.form['password']
#         UserName = email.split("@")[0]
    
#         PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password) else True
#         ExistingEmailID = True if mongo.db.Staffs.find_one({'Email': email}) else False

#         if PasswordCheck  or ExistingEmailID:
#             ErrorMessages = []
#             if PasswordCheck:
#                 ErrorMessages.append('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.')
#             if ExistingEmailID:
#                 ErrorMessages.append('Email ID already Registered. Try Logging in.')
#             flash(ErrorMessages, 'error')
#             return redirect(url_for('staffs.Registration'))

#         passwordH = SHA256.HashPassword(password, UserName)

#         SendVerificationEmail(UserName, email, GenerateVerificationCode())

#         mongo.db.Staffs.insert_one({
#             'UserName': UserName,
#             'first_name': name, 
#             'Email': email, 
#             'Password': passwordH, 
#         })


#         return redirect(url_for('staffs.VerifyAccount', UserName=UserName))
#     return render_template('staffs/Register.html')

@StaffsBP.route('/verifyaccount/<UserName>', methods=['GET', 'POST'])
@NotLoggedInUser
def VerifyAccount(UserName):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = mongo.db.StaffVerification.find_one({'UserName': UserName, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('staffs.Login', UserName=UserName))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            mongo.db.StaffVerification.update_one({'UserName': UserName}, {'$set': {'Verified': True}})
            return redirect(url_for('staffs.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('staffs.VerifyAccount', UserName=UserName))

    return render_template('staffs/VerifyAccount.html', UserName=UserName)

@StaffsBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInUser
def Login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        currenttime = datetime.now(timezone.utc)

        if "@" in login:
            user = mongo.db.Staffs.find_one({'Email': login})
        else:
            user = mongo.db.Staffs.find_one({'UserName': login})

        if not user:
            flash('Invalid Login or Password', 'error')
            return redirect(url_for('staffs.Login'))
        
        if not IsUserVerified(user["UserName"]):
            flash('User not verified! Please complete the OTP verification', 'error')
            return redirect(url_for('staffs.VerifyAccount', UserName=user["UserName"]))

        if SHA256.CheckPassword(password, user["Password"], user["UserName"]):
            sessionkey = GenerateSessionKey()  
            mongo.db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                'UserName': user["UserName"],
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            }) 
            mongo.db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            session['SessionKey'] = sessionkey
            session['UserName'] = user["UserName"]

            return redirect(url_for('staffs.Index'))
        else:
            flash('Invalid Login or password', 'error')
    return render_template('staffs/Login.html')

@StaffsBP.route('/forgotpassword', methods=['GET', 'POST'])
@NotLoggedInUser
def ForgotPassword():
    if request.method == 'POST':
        login = request.form['login']

        if "@" in login:
            user = mongo.db.Staffs.find_one({'Email': login})
        else:
            user = mongo.db.Staffs.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Email ID', 'error')
            return redirect(url_for('staffs.ForgotPassword'))

        ResetKey = AES256.GenerateRandomString(32)
        PasswordResetMail(user["UserName"], user["Email"], ResetKey)

        flash('A Password Reset Link has been sent to your Email! Please check your Inbox and Follow the Instructions', 'info')
    return render_template('staffs/ForgotPassword.html')

@StaffsBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
@NotLoggedInUser
def ResetPassword(ResetKey):
    if request.method == 'POST':
        NewPassword = request.form['password']
            
        ResetData = mongo.db.PasswordReset.find_one({'ResetKey': ResetKey})

        if not ResetData:
            flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('staffs.ResetPassword', ResetKey=ResetKey))
        
        user = mongo.db.Staffs.find_one({'UserName': ResetData['UserName']})

        passwordH = SHA256.HashPassword(NewPassword, user["UserName"])

        mongo.db.Staffs.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordH}})

        mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
        flash('Password reset successful. Try Loggin in.', 'info')
        return redirect(url_for('staffs.Login'))
    return render_template('staffs/ResetPassword.html', ResetKey=ResetKey)

@StaffsBP.route('/logout')
@LoggedInUser
def Logout():
    session_key = session['SessionKey']
    user_name = session['UserName']
    mongo.db.UserSessions.delete_one({
        'SessionKey': session_key,
        'UserName': user_name
    })
    session.clear()
    return redirect(url_for('staffs.Index'))