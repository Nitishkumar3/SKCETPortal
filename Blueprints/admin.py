from flask import render_template, request, redirect, url_for, session, flash, send_from_directory, Blueprint
from functools import wraps
from datetime import datetime, timedelta, timezone
import secrets
from db import mongo
from Modules import AES256, SHA256, Mail
import string
import re

AdminBP = Blueprint('admin', __name__)

def GenerateSessionKey(length=32):
    SessionKey = secrets.token_hex(length // 2)
    return SessionKey

def GenerateVerificationCode(length=32):
    characters = string.ascii_letters + string.digits
    VerificationCode = ''.join(secrets.choice(characters) for _ in range(length))
    return VerificationCode

def SendVerificationEmail(rollnumber, email, VerificationCode):
    subject = "SKCET - Verify your Account"
    body = "Verification Code: " + str(VerificationCode)
    if Mail.SendMail(subject, body, email):
        mongo.db.StaffVerification.insert_one({'RollNumber': rollnumber, 'VerificationCode': VerificationCode, 'Verified': False})

def IsUserVerified(rollnumber):
    VerifiedStatus = mongo.db.StaffVerification.find_one({'RollNumber': rollnumber, 'Verified': True})
    return VerifiedStatus is not None

def PasswordResetMail(rollnumber, email, ResetKey):
    subject = "SKCET - Password Reset"
    link = "http://localhost:5000/resetkey/" + str(ResetKey)
    body = "Password Reset Code: " + str(ResetKey) + f" {link}"
    if Mail.SendMail(subject, body, email):
        currenttime = datetime.utcnow()
        mongo.db.PasswordReset.insert_one({'RollNumber': rollnumber, 'ResetKey': ResetKey, 'CreatedAt': currenttime, 'ExpirationTime': currenttime + timedelta(hours=6)})
        mongo.db.PasswordReset.create_index('ExpirationTime', expireAfterSeconds=0)

def LoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'RollNumber' in session:
            session_key = session['SessionKey']
            roll_number = session['RollNumber']
            user_session = mongo.db.UserSessions.find_one({
                'SessionKey': session_key,
                'RollNumber': roll_number,
                'ExpirationTime': {'$gt': datetime.now(timezone.utc)}
            })
            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('admin.Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('admin.Login'))
    return decorated_function

def NotLoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'RollNumber' in session:
            return redirect(url_for('admin.Dashboard'))
        return view_func(*args, **kwargs)
    return decorated_function

@AdminBP.route('/', methods=["GET", "POST"])
@LoggedInUser
def Dashboard():
    if request.method == 'POST':
        name =  request.form['name']
        email =  request.form['email']
        password = request.form['password']
        UserName = email.split("@")[0]
        degree = request.form['degree']
        department = request.form['department']
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password) else True
        ExistingEmailID = True if mongo.db.Staffs.find_one({'Email': email}) else False

        ErrorMessages = []
        if PasswordCheck  or ExistingEmailID:
            if PasswordCheck:
                ErrorMessages.append('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.')
            if ExistingEmailID:
                ErrorMessages.append('Email ID already Registered. Try Logging in.')
            flash(ErrorMessages, 'error')
            return redirect(url_for('admin.Dashboard'))

        passwordH = SHA256.HashPassword(password, UserName)

        SendVerificationEmail(UserName, email, GenerateVerificationCode())

        mongo.db.Staffs.insert_one({
            'UserName': UserName,
            "RollNumber": UserName,
            'first_name': name, 
            'Email': email, 
            'Password': passwordH,
            'Degree': degree,
            'Department': department
        })

        ErrorMessages.append('Account Created!')
        flash(ErrorMessages, 'error')
    return render_template('admin/AddStaff.html')

@AdminBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInUser
def Login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        currenttime = datetime.now(timezone.utc)

        if not (login == "admin@skcet.ac.in" or login == "admin"):
            flash('Invalid Login or Password', 'error')
            return redirect(url_for('admin.Login'))

        if password=="Skcet!123":
            sessionkey = GenerateSessionKey()  
            mongo.db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                'RollNumber': "admin",
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            }) 
            mongo.db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            session['SessionKey'] = sessionkey
            session['RollNumber'] = "admin"

            return redirect(url_for('admin.Dashboard'))
        else:
            flash('Invalid Login or password', 'error')
    return render_template('students/Login.html')

@AdminBP.route('/logout')
@LoggedInUser
def Logout():
    session_key = session['SessionKey']
    roll_number = session['RollNumber']
    mongo.db.UserSessions.delete_one({
        'SessionKey': session_key,
        'RollNumber': roll_number
    })
    session.clear()
    return redirect(url_for('admin.Login'))