from flask import render_template, request, redirect, url_for, session, flash, send_from_directory, Blueprint
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta, timezone
from Modules import AES256, SHA256, Mail
import re
import secrets
import string
from db import mongo
from bson import ObjectId
import random

StudentsBP = Blueprint('students', __name__)

def AllowedFile(Filename):
    return '.' in Filename and Filename.rsplit('.', 1)[1].lower() in StudentsBP.app.config['ALLOWED_EXTENSIONS']

def GenerateRandomFilename(Extension):
    Characters = string.ascii_letters + string.digits
    RandomString = ''.join(random.choice(Characters) for _ in range(8))
    return f"{RandomString}.{Extension}"

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
                return redirect(url_for('students.Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('students.Login'))
    return decorated_function

def NotLoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKey' in session and 'RollNumber' in session:
            return redirect(url_for('students.Dashboard'))
        return view_func(*args, **kwargs)
    return decorated_function

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
        mongo.db.StudentVerification.insert_one({'RollNumber': rollnumber, 'VerificationCode': VerificationCode, 'Verified': False})

def IsUserVerified(rollnumber):
    VerifiedStatus = mongo.db.StudentVerification.find_one({'RollNumber': rollnumber, 'Verified': True})
    return VerifiedStatus is not None

def PasswordResetMail(rollnumber, email, ResetKey):
    subject = "SKCET - Password Reset"
    link = "http://localhost:5000/resetkey/" + str(ResetKey)
    body = "Password Reset Code: " + str(ResetKey) + f" {link}"
    if Mail.SendMail(subject, body, email):
        currenttime = datetime.utcnow()
        mongo.db.PasswordReset.insert_one({'RollNumber': rollnumber, 'ResetKey': ResetKey, 'CreatedAt': currenttime, 'ExpirationTime': currenttime + timedelta(hours=6)})
        mongo.db.PasswordReset.create_index('ExpirationTime', expireAfterSeconds=0)

def ToShortCode(Degree, Department):
    if Degree == "B.Tech" and Department == "Information Technology (IT)":
        return "IT"
    elif Degree == "B.E." and Department == "Civil Engineering":
        return "Civil"
    elif Degree == "B.E." and Department == "Computer Science and Design (CSD)":
        return "CSD"
    elif Degree == "B.E." and Department == "Computer Science and Engineering (CSE)":
        return "CSE"
    elif Degree == "M.Tech Integrated" and Department == "Computer Science and Engineering (CSE)":
        return "MTechCSE"
    elif Degree == "B.E." and Department == "Cyber Security (CSY)":
        return "CSY"
    elif Degree == "B.E." and Department == "Electrical and Electronics Engineering (EEE)":
        return "EEE"
    elif Degree == "B.E." and Department == "Electronics and Communication Engineering (ECE)":
        return "ECE"
    elif Degree == "B.E." and Department == "Mechanical Engineering":
        return "Mech"
    elif Degree == "B.E." and Department == "Mechatronics Engineering":
        return "Mect"
    elif Degree == "B.Tech" and Department == "Artificial Intelligence And Data Science (AI & DS)":
        return "AIDS"
    elif Degree == "B.Tech" and Department == "Computer Science and Business Systems (CSBS)":
        return "CSBS"
    else:
        return ""

@StudentsBP.route('/register', methods=['GET', 'POST'])
@NotLoggedInUser
def Registration():
    if request.method == 'POST':
        name =  request.form['name']
        email =  request.form['email']
        password = request.form['password']
        rollnumber = email.split("@")[0]
    
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password) else True
        ExistingEmailID = True if mongo.db.StudentDetails.find_one({'Email': email}) else False

        if PasswordCheck  or ExistingEmailID:
            ErrorMessages = []
            if PasswordCheck:
                ErrorMessages.append('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.')
            if ExistingEmailID:
                ErrorMessages.append('Email ID already Registered. Try Logging in.')
            flash(ErrorMessages, 'error')
            return redirect(url_for('students.Registration'))

        passwordH = SHA256.HashPassword(password, rollnumber)

        SendVerificationEmail(rollnumber, email, GenerateVerificationCode())

        mongo.db.StudentDetails.insert_one({
            'RollNumber': rollnumber,
            'first_name': name, 
            'Email': email, 
            'Password': passwordH, 
        })


        return redirect(url_for('students.VerifyAccount', rollnumber=rollnumber))
    return render_template('students/Register.html')

@StudentsBP.route('/verifyaccount/<rollnumber>', methods=['GET', 'POST'])
@NotLoggedInUser
def VerifyAccount(rollnumber):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = mongo.db.StudentVerification.find_one({'RollNumber': rollnumber, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('students.Login', rollnumber=rollnumber))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            mongo.db.StudentVerification.update_one({'RollNumber': rollnumber}, {'$set': {'Verified': True}})
            return redirect(url_for('students.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('students.VerifyAccount', rollnumber=rollnumber))

    return render_template('students/VerifyAccount.html', rollnumber=rollnumber)

@StudentsBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInUser
def Login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        currenttime = datetime.now(timezone.utc)

        if "@" in login:
            user = mongo.db.StudentDetails.find_one({'Email': login})
        else:
            user = mongo.db.StudentDetails.find_one({'RollNumber': login})

        if not user:
            flash('Invalid Login or Password', 'error')
            return redirect(url_for('students.Login'))
        
        if not IsUserVerified(user["RollNumber"]):
            flash('User not verified! Please complete the OTP verification', 'error')
            return redirect(url_for('students.VerifyAccount', rollnumber=user["RollNumber"]))

        if SHA256.CheckPassword(password, user["Password"], user["RollNumber"]):
            sessionkey = GenerateSessionKey()  
            mongo.db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                'RollNumber': user["RollNumber"],
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            }) 
            mongo.db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            session['SessionKey'] = sessionkey
            session['RollNumber'] = user["RollNumber"]

            return redirect(url_for('students.Dashboard'))
        else:
            flash('Invalid Login or password', 'error')
    return render_template('students/Login.html')

# from Modules.Mail import SendMail


# @StudentsBP.route('/forgotpassword', methods=['GET', 'POST'])
# @NotLoggedInUser
# def ForgotPassword():
#     if request.method == 'POST':
#         login = request.form['login']

#         if "@" in login:
#             user = mongo.db.StudentDetails.find_one({'Email': login})
#         else:
#             user = mongo.db.StudentDetails.find_one({'RollNumber': login})

#         if not user:
#             flash('Invalid Username or Email ID', 'error')
#             return redirect(url_for('students.ForgotPassword'))

#         ResetKey = AES256.GenerateRandomString(32)
#         PasswordResetMail(user["RollNumber"], user["Email"], ResetKey)

#         flash('A Password Reset Link has been sent to your Email! Please check your Inbox and Follow the Instructions', 'info')
#     return render_template('students/ForgotPassword.html')


# def PasswordResetMail(roll_number, email, reset_key):
#     subject = "Reset Your Password - SKCET"
#     reset_link = url_for('students.ResetPassword', key=reset_key, _external=True)
    
#     # Plain text version
#     plain_text = f"""
#     Reset Your Password - SKCET

#     We received a request to reset your password. Use the link below to set up a new password for your account:

#     {reset_link}

#     If you didn't request this, you can safely ignore this email.

#     This password reset link will expire in 24 hours.

#     SKCET Team
#     """

#     # HTML version
#     html_content = render_template('email/forgot_password_email.html', reset_link=reset_link)

#     SendMail(subject, plain_text, email, html_content)

# def PasswordResetConfirmationMail(email):
#     subject = "Password Reset Successful - SKCET"
#     login_link = url_for('students.Login', _external=True)
    
#     # Plain text version
#     plain_text = f"""
#     Password Reset Successful - SKCET

#     Your password has been successfully reset.

#     If you did not perform this action, please contact our support team immediately.

#     Log in to your account: {login_link}

#     SKCET Team
#     """

#     # HTML version
#     html_content = render_template('email/reset_password_confirmation_email.html', login_link=login_link)

#     SendMail(subject, plain_text, email, html_content)

# @StudentsBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
# @NotLoggedInUser
# def ResetPassword(ResetKey):
#     if request.method == 'POST':
#         NewPassword = request.form['password']
            
#         ResetData = mongo.db.PasswordReset.find_one({'ResetKey': ResetKey})

#         if not ResetData:
#             flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
        
#         PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

#         if PasswordCheck:
#             flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
#             return redirect(url_for('students.ResetPassword', ResetKey=ResetKey))
        
#         user = mongo.db.StudentDetails.find_one({'RollNumber': ResetData['RollNumber']})

#         passwordH = SHA256.HashPassword(NewPassword, user["RollNumber"])

#         mongo.db.StudentDetails.update_one({'RollNumber': ResetData['RollNumber']}, {'$set': {'Password': passwordH}})

#         mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
#         flash('Password reset successful. Try Loggin in.', 'info')
#         return redirect(url_for('students.Login'))
#     return render_template('students/ResetPassword.html', ResetKey=ResetKey)


from flask import flash, redirect, url_for, render_template, request
from Modules.Mail import SendMail
from Modules import AES256, SHA256
import re

@StudentsBP.route('/forgotpassword', methods=['GET', 'POST'])
@NotLoggedInUser
def ForgotPassword():
    if request.method == 'POST':
        login = request.form['login']

        if "@" in login:
            user = mongo.db.StudentDetails.find_one({'Email': login})
        else:
            user = mongo.db.StudentDetails.find_one({'RollNumber': login})

        if not user:
            flash('Invalid Username or Email ID', 'error')
            return redirect(url_for('students.ForgotPassword'))

        ResetKey = AES256.GenerateRandomString(32)
        
        # Store the reset key in the database
        mongo.db.PasswordReset.insert_one({
            'RollNumber': user['RollNumber'],
            'ResetKey': ResetKey,
            'CreatedAt': datetime.utcnow()
        })

        # Send password reset email
        PasswordResetMail(user["RollNumber"], user["Email"], ResetKey)

        flash('A Password Reset Link has been sent to your Email! Please check your Inbox and Follow the Instructions', 'info')
    return render_template('students/ForgotPassword.html')

@StudentsBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
@NotLoggedInUser
def ResetPassword(ResetKey):
    if request.method == 'POST':
        NewPassword = request.form['password']
            
        ResetData = mongo.db.PasswordReset.find_one({'ResetKey': ResetKey})

        if not ResetData:
            flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
            return redirect(url_for('students.ForgotPassword'))
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('students.ResetPassword', ResetKey=ResetKey))
        
        user = mongo.db.StudentDetails.find_one({'RollNumber': ResetData['RollNumber']})

        passwordH = SHA256.HashPassword(NewPassword, user["RollNumber"])

        mongo.db.StudentDetails.update_one({'RollNumber': ResetData['RollNumber']}, {'$set': {'Password': passwordH}})

        mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
        # Send password reset confirmation email
        PasswordResetConfirmationMail(user["Email"])
        
        flash('Password reset successful. You can now log in with your new password.', 'success')
        return redirect(url_for('students.Login'))
    return render_template('students/ResetPassword.html', ResetKey=ResetKey)

def PasswordResetMail(roll_number, email, reset_key):
    subject = "Reset Your Password - SKCET"
    reset_link = url_for('students.ResetPassword', ResetKey=reset_key, _external=True)
    
    # Plain text version
    plain_text = f"""
    Reset Your Password - SKCET

    We received a request to reset your password. Use the link below to set up a new password for your account:

    {reset_link}

    If you didn't request this, you can safely ignore this email.

    This password reset link will expire in 24 hours.

    SKCET Team
    """

    # HTML version
    html_content = render_template('email/PasswordResetEmail.html', reset_link=reset_link)

    SendMail(subject, plain_text, email, html_content)

def PasswordResetConfirmationMail(email):
    subject = "Password Reset Successful - SKCET"
    login_link = url_for('students.Login', _external=True)
    
    # Plain text version
    plain_text = f"""
    Password Reset Successful - SKCET

    Your password has been successfully reset.

    If you did not perform this action, please contact our support team immediately.

    Log in to your account: {login_link}

    SKCET Team
    """

    # HTML version
    html_content = render_template('email/ResetPasswordConfirmationEmail.html', login_link=login_link)

    SendMail(subject, plain_text, email, html_content)




@StudentsBP.route('/logout')
@LoggedInUser
def Logout():
    session_key = session['SessionKey']
    roll_number = session['RollNumber']
    mongo.db.UserSessions.delete_one({
        'SessionKey': session_key,
        'RollNumber': roll_number
    })
    session.clear()
    return redirect(url_for('Index'))

@StudentsBP.route('/profile')
@LoggedInUser
def Profile():
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})
    if user:
        # decrypted_data = {}
        # for key, value in user.items():
        #     if key not in ["_id", "RollNumber", "Email", "Password"]:
        #         decrypted_data[f"{key}"] = AES256.Decrypt(value, AES256.DeriveKey(rollnumber, f"{key}"))
        #     elif key in ["RollNumber", "Email"]:
        #         decrypted_data[f"{key}"] = value
        # name = decrypted_data["first_name"]
        # if decrypted_data.get("last_name"):
        #     name += " " + decrypted_data["last_name"]
        name = user["first_name"]
        if user.get("last_name"):
            name += " " + user["last_name"]
        return render_template('students/Profile/Index.html', data = user, name = name)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('students.Login'))

@StudentsBP.route('/profile/edit', methods=['GET', 'POST'])
@LoggedInUser
def EditProfile():
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})

    if request.method == 'POST':
        personal_details = {
            'first_name': request.form.get('first-name', ''),
            'last_name': request.form.get('last-name', ''),
            'RollNumber': request.form.get('register-number', ''),
            'mobile_number': request.form.get('mobile-number', ''),
            'gender': request.form.get('gender', ''),
            'dob': request.form.get('dob', ''),
            'personal_email': request.form.get('personal-email', ''),
            'Email': request.form.get('college-email', ''),
            'first_graduate': request.form.get('first-graduate', ''),
            'emis_number': request.form.get('emis-number', ''),
            'religion': request.form.get('religion', ''),
            'community': request.form.get('community', ''),
            'sub_caste': request.form.get('sub-caste', ''),
            'nationality': request.form.get('nationality', ''),
            'country_name': request.form.get('country-name', 'India')
        }

        government_ids = {
            'aadhaar_number': request.form.get('aadhaar-number', ''),
            'pan_number': request.form.get('pan-number', ''),
            'voter_id': request.form.get('voter-id', '')
        }
        
        address = {
            'permanent_address': request.form.get('permanent-address', ''),
            'city': request.form.get('city', ''),
            'state': request.form.get('state', ''),
            'postal_code': request.form.get('postal-code', ''),
            'communication_address': request.form.get('communication-address', ''),
            'communication_city': request.form.get('communication-city', ''),
            'communication_state': request.form.get('communication-state', ''),
            'communication_postal_code': request.form.get('communication-postal-code', ''),
        }  

        parent_details = {
            'father_name': request.form.get('father-name', ''),
            'father_mobile': request.form.get('father-mobile', ''),
            'mother_name': request.form.get('mother-name', ''),
            'mother_mobile': request.form.get('mother-mobile', ''),
            'father_occupation': request.form.get('father-occupation', ''),
            'mother_occupation': request.form.get('mother-occupation', ''),
            'guardian_name': request.form.get('guardian-name', ''),
            'guardian_mobile': request.form.get('guardian-mobile', ''),
            'orphan': request.form.get('orphan', ''),
            'annual_income': request.form.get('annual-income', '')
        }

        health_details = {
            'health_issues': request.form.get('health-issues', ''),
            'health_issues_details': request.form.get('health-issues-details', '')
        }

        disability = { 
            'differently_abled': request.form.get('differently-abled', ''),
            'disability_type': request.form.get('disability-type', ''),
            'disability_percentage': request.form.get('disability-percentage', ''),
            'udid': request.form.get('udid', '')
        }

        bank_details = {
            'bank_account_name': request.form.get('bank-account-name', ''),
            'bank_name': request.form.get('bank-name', ''),
            'branch': request.form.get('branch', ''),
            'account_number': request.form.get('account-number', ''),
            'ifsc_code': request.form.get('ifsc-code', '')
        }

        admission_details = {
            'degree': request.form['degree'],
            'department': request.form['department'],
            'section': request.form['section'],
            'batch': request.form['batch'],
            'admission_mode': request.form['admission-mode'],
            'quota': request.form['quota'],
            'course_type': request.form['course-type'],
            'lateral_entry': request.form['lateral-entry'],
            'date_of_admission': request.form['date-of-admission'],
            'tnea_application_number': request.form['tnea-application-number'],
        }

        hostel_details = {
            'hosteller': request.form['hosteller'],
            'hostel_type': request.form['hostel-type'],
            'pg_address': request.form['pg-address']
        }

        status = {
            'status': request.form['status']
        }

        data = {}

        data.update(personal_details)
        data.update(government_ids)
        data.update(address)
        data.update(parent_details)
        data.update(health_details)
        data.update(disability)
        data.update(bank_details)
        data.update(admission_details)
        data.update(hostel_details)
        data.update(status)

        # encrypted_data = {}
        # for key, value in data.items():
        #     if key not in ["_id", "RollNumber", "Email", "Password"]:
        #         encrypted_data[f"{key}"] = AES256.Encrypt(value, AES256.DeriveKey(rollnumber, f"{key}"))
        #     elif key in ["RollNumber", "Email"]:
        #         encrypted_data[f"{key}"] = value

        # Upsert data into the database
        mongo.db.StudentDetails.update_one({'RollNumber': rollnumber}, {'$set': data}, upsert=True) # encrypted_data -> data

        return redirect(url_for('students.Profile'))
    elif request.method == 'GET':

        # decrypted_data = {}
        # for key, value in user.items():
        #     if key not in ["_id", "RollNumber", "Email", "Password"]:
        #         decrypted_data[f"{key}"] = AES256.Decrypt(value, AES256.DeriveKey(rollnumber, f"{key}"))
        #     elif key in ["RollNumber", "Email"]:
        #         decrypted_data[f"{key}"] = value
        # name = decrypted_data["first_name"]
        # if decrypted_data.get("last_name"):
        #     name += " " + decrypted_data["last_name"]
        name = user["first_name"]
        if user.get("last_name"):
            name += " " + user["last_name"]
        return render_template('students/Profile/Edit.html', data = user, name = name)


schedule = {
    "Monday": [
        {"start": "09:00", "end": "09:40", "title": "SVT"},
        {"start": "09:40", "end": "10:35", "title": "BDA LAB"},
        {"start": "10:35", "end": "11:00", "title": "Break"},
        {"start": "11:00", "end": "11:55", "title": "BDA LAB"},
        {"start": "11:55", "end": "12:50", "title": "BDA LAB"},
        {"start": "12:50", "end": "13:50", "title": "Break"},
        {"start": "13:50", "end": "14:45", "title": "SVT"},
        {"start": "14:45", "end": "15:35", "title": "WSN"},
        {"start": "15:35", "end": "16:30", "title": "MAD"}
    ],
    "Tuesday": [
        {"start": "09:00", "end": "09:40", "title": "CD"},
        {"start": "09:40", "end": "10:35", "title": "CNS"},
        {"start": "10:35", "end": "11:00", "title": "Break"},
        {"start": "11:00", "end": "11:55", "title": "MAD"},
        {"start": "11:55", "end": "12:50", "title": "BDA"},
        {"start": "12:50", "end": "13:50", "title": "Break"},
        {"start": "13:50", "end": "14:45", "title": "WSN"},
        {"start": "14:45", "end": "15:35", "title": "BDA"},
        {"start": "15:35", "end": "16:30", "title": "CD"}
    ],
    "Wednesday": [
        {"start": "09:00", "end": "09:40", "title": "SVT"},
        {"start": "09:40", "end": "10:35", "title": "CD"},
        {"start": "10:35", "end": "11:00", "title": "Break"},
        {"start": "11:00", "end": "11:55", "title": "CNS"},
        {"start": "11:55", "end": "12:50", "title": "WSN"},
        {"start": "12:50", "end": "13:50", "title": "Break"},
        {"start": "13:50", "end": "14:45", "title": "SVT"},
        {"start": "14:45", "end": "15:35", "title": "MAD"},
        {"start": "15:35", "end": "16:30", "title": "MAD LAB"}
    ],
    "Thursday": [
        {"start": "09:00", "end": "09:40", "title": "CNS"},
        {"start": "09:40", "end": "10:35", "title": "WSN"},
        {"start": "10:35", "end": "11:00", "title": "Break"},
        {"start": "11:00", "end": "11:55", "title": "BDA"},
        {"start": "11:55", "end": "12:50", "title": "CD"},
        {"start": "12:50", "end": "13:50", "title": "Break"},
        {"start": "13:50", "end": "14:45", "title": "BDA"},
        {"start": "14:45", "end": "15:35", "title": "CD"},
        {"start": "15:35", "end": "16:30", "title": "MAD"}
    ],
    "Friday": [
        {"start": "09:00", "end": "09:40", "title": "WSN"},
        {"start": "09:40", "end": "10:35", "title": "MINI PROJECT"},
        {"start": "10:35", "end": "11:00", "title": "Break"},
        {"start": "11:00", "end": "11:55", "title": "MINI PROJECT"},
        {"start": "11:55", "end": "12:50", "title": "MINI PROJECT"},
        {"start": "12:50", "end": "13:50", "title": "Break"},
        {"start": "13:50", "end": "14:45", "title": "SVT"},
        {"start": "14:45", "end": "15:35", "title": "CNS"},
        {"start": "15:35", "end": "16:30", "title": "BDA"}
    ]
}

articles = [
    {
        "cover_pic": "https://dummyimage.com/800x450/000/fff",
        "date": "Mar 16, 2024",
        "department": "Marketing",
        "title": "Boost Your Social Media Presence",
        "description": "Learn effective strategies to enhance your brand's social media engagement and reach.",
        "author_pic": "https://dummyimage.com/100x100/000/fff",
        "author": "Jane Doe",
        "designation": "Social Media Specialist"
    },
    {
        "cover_pic": "https://dummyimage.com/800x450/000/fff",
        "date": "Apr 22, 2024",
        "department": "Technology",
        "title": "The Future of AI in Business",
        "description": "Explore how artificial intelligence is reshaping various industries and what it means for your business.",
        "author_pic": "https://dummyimage.com/100x100/000/fff",
        "author": "John Smith",
        "designation": "AI Researcher"
    },
    {
        "cover_pic": "https://dummyimage.com/800x450/000/fff",
        "date": "May 5, 2024",
        "department": "Finance",
        "title": "Investment Strategies for 2024",
        "description": "Discover the latest trends and expert advice on where to invest your money in the current economic climate.",
        "author_pic": "https://dummyimage.com/100x100/000/fff",
        "author": "Emma Johnson",
        "designation": "Financial Advisor"
    }
]

announcements = [
    {
        "name": "Eduardo Benz",
        "time": datetime.now() - timedelta(days=6),
        "info": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Tincidunt nunc ipsum tempor purus vitae id. Morbi in vestibulum nec varius. Et diam cursus quis sed purus nam.",
        "dp_url": "https://images.unsplash.com/photo-1520785643438-5bf77931f493?ixlib=rb-=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=facearea&facepad=8&w=256&h=256&q=80"
    },
    {
        "name": "Jason Meyers",
        "time": datetime.now() - timedelta(hours=2),
        "info": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Tincidunt nunc ipsum tempor purus vitae id. Morbi in vestibulum nec varius. Et diam cursus quis sed purus nam. Scelerisque amet elit non sit ut tincidunt condimentum. Nisl ultrices eu venenatis diam.",
        "dp_url": "https://images.unsplash.com/photo-1531427186611-ecfd6d936c79?ixlib=rb-=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=facearea&facepad=8&w=256&h=256&q=80"
    },
    {
        "name": "Alice Johnson",
        "time": datetime.now() - timedelta(minutes=30),
        "info": "Quick update on the project. Everything is going well!",
        "dp_url": "https://images.unsplash.com/photo-1517841905240-472988babdf9?ixlib=rb-=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=facearea&facepad=8&w=256&h=256&q=80"
    },
]  

@StudentsBP.route('/dashboard')
@LoggedInUser
def Dashboard():
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})
    name = user["first_name"]
    if user.get("last_name"):
        name += " " + user["last_name"]

    return render_template('students/Dashboard.html', name=name, schedule=schedule, articles=articles, announcements=announcements)

@StudentsBP.route('/timetable')
@LoggedInUser
def Timetable():
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})
    name = user["first_name"]
    if user.get("last_name"):
        name += " " + user["last_name"]

    return render_template('students/Timetable/Index.html', name=name, schedule=schedule)

@StudentsBP.route('/hackathons')
@LoggedInUser
def Hackathons():
    RollNumber = session['RollNumber'].upper()
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})
    name = user["first_name"]
    if user.get("last_name"):
        name += " " + user["last_name"]

    results = list(mongo.db.HackathonParticipations.find({"TeamDetails": RollNumber}))
    for index, item in enumerate(results, start=1):
        item['sno'] = index

    # Convert ObjectId to string
    for result in results:
        if '_id' in result:
            result['_id'] = str(result['_id'])
    return render_template('students/Hackathons/Index.html', hackathons=results, RollNumber=RollNumber, name = name)

@StudentsBP.route('/hackathons/add', methods=['GET', 'POST'])
@LoggedInUser
def HackathonsAdd():
    RollNumber = session['RollNumber'].upper()
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})
    name = user["first_name"]
    if user.get("last_name"):
        name += " " + user["last_name"]

    if request.method == 'POST':
        Characters = string.ascii_letters + string.digits
        ID = ''.join(random.choice(Characters) for _ in range(8))
        
        TeamDetails = request.form.getlist('TeamDetails[]')
        FormattedTeamDetails = [item.upper() for item in TeamDetails]

        LeaderEmail = str(FormattedTeamDetails[0].lower()) + "@skcet.ac.in"
        Leader = mongo.db.StudentDetails.find_one({'Email': LeaderEmail})
        DeptShortCode = ToShortCode(Leader["degree"], Leader["department"])

        EventData = {
            'ID': ID,
            'EventName': request.form['EventName'],
            'TeamName': request.form['TeamName'],
            'ProjectTitle': request.form['ProjectTitle'],
            'Date': request.form['Date'],
            'Mode': request.form['Mode'],
            'TeamDetails': FormattedTeamDetails,
            'Status': request.form['Status'],
            'EventPhotos': [],
            'CertificatePhotos': [],
            'Department': DeptShortCode, 
        }

        if EventData['Mode'] == 'Offline':
            EventData['Venue'] = request.form['Venue']

        if EventData['Status'] == 'EventCompleted':
            EventData['ParticipatedWon'] = request.form['ParticipatedWon']

            if EventData['ParticipatedWon'] == 'Won':
                EventData['Position'] = request.form['Position']
                EventData['PrizeAmount'] = request.form['PrizeAmount']

            # Handle event photos
            EventPhotos = request.files.getlist('EventPhotos')
            for Photo in EventPhotos[:3]:  # Limit to 5 photos
                if Photo and AllowedFile(Photo.filename):
                    Extension = Photo.filename.rsplit('.', 1)[1].lower()
                    Filename = GenerateRandomFilename(Extension)
                    Photo.save(os.path.join(StudentsBP.app.config['EVENT_PICS_FOLDER'], Filename))
                    EventData['EventPhotos'].append(url_for('static', filename=f'uploads/eventpics/{Filename}'))

            # Handle certificate photos
            CertificatePhotos = request.files.getlist('CertificatePhotos')
            for Photo in CertificatePhotos[:3]:  # Limit to 5 photos
                if Photo and AllowedFile(Photo.filename):
                    Extension = Photo.filename.rsplit('.', 1)[1].lower()
                    Filename = GenerateRandomFilename(Extension)
                    Photo.save(os.path.join(StudentsBP.app.config['CERTIFICATE_PICS_FOLDER'], Filename))
                    EventData['CertificatePhotos'].append(url_for('static', filename=f'uploads/certificatepics/{Filename}'))

        # Insert data into MongoDB
        mongo.db.HackathonParticipations.insert_one(EventData)
        return redirect(url_for('students.Hackathons'))

    return render_template('students/Hackathons/Add.html', RollNumber=RollNumber, name = name)

@StudentsBP.route('/hackathon/<string:id>')
@LoggedInUser
def ViewHackathon(id):
    hackathon = mongo.db.HackathonParticipations.find_one({"_id": ObjectId(id)})
    return render_template('students/Hackathons/View.html', hackathon=hackathon)

@StudentsBP.route('/hackathons/edit/<string:id>', methods=['GET', 'POST'])
@LoggedInUser
def EditHackathon(id):
    RollNumber = session['RollNumber']
    rollnumber = session['RollNumber']
    user = mongo.db.StudentDetails.find_one({'RollNumber': rollnumber})
    name = user["first_name"]
    if user.get("last_name"):
        name += " " + user["last_name"]

    hackathon = mongo.db.HackathonParticipations.find_one({"_id": ObjectId(id)})
   
    if request.method == 'POST':
        TeamDetails = request.form.getlist('TeamDetails[]')
        FormattedTeamDetails = [item.upper() for item in TeamDetails]

        LeaderEmail = str(FormattedTeamDetails[0].lower()) + "@skcet.ac.in"
        Leader = mongo.db.StudentDetails.find_one({'Email': LeaderEmail})
        DeptShortCode = ToShortCode(Leader["degree"], Leader["department"])

        EventData = {
            'EventName': request.form['EventName'],
            'TeamName': request.form['TeamName'],
            'ProjectTitle': request.form['ProjectTitle'],
            'Date': request.form['Date'],
            'Mode': request.form['Mode'],
            'TeamDetails': FormattedTeamDetails,
            'Status': request.form['Status'],
            'Department': DeptShortCode,
        }
       
        if EventData['Mode'] == 'Offline':
            EventData['Venue'] = request.form['Venue']
        else:
            EventData['Venue'] = None
       
        if EventData['Status'] == 'EventCompleted':
            EventData['ParticipatedWon'] = request.form['ParticipatedWon']
            if EventData['ParticipatedWon'] == 'Won':
                EventData['Position'] = request.form['Position']
                EventData['PrizeAmount'] = request.form['PrizeAmount']
            else:
                EventData['Position'] = None
                EventData['PrizeAmount'] = None
           
            # Handle event photos
            EventPhotos = request.files.getlist('EventPhotos')
            EventData['EventPhotos'] = hackathon.get('EventPhotos', [])
            for Photo in EventPhotos:
                if Photo and AllowedFile(Photo.filename):
                    Extension = Photo.filename.rsplit('.', 1)[1].lower()
                    Filename = GenerateRandomFilename(Extension)
                    Photo.save(os.path.join(StudentsBP.app.config['EVENT_PICS_FOLDER'], Filename))
                    EventData['EventPhotos'].append(url_for('static', filename=f'uploads/eventpics/{Filename}'))
            EventData['EventPhotos'] = EventData['EventPhotos'][:5]  # Limit to 5 photos
           
            # Handle certificate photos
            CertificatePhotos = request.files.getlist('CertificatePhotos')
            EventData['CertificatePhotos'] = hackathon.get('CertificatePhotos', [])
            for Photo in CertificatePhotos:
                if Photo and AllowedFile(Photo.filename):
                    Extension = Photo.filename.rsplit('.', 1)[1].lower()
                    Filename = GenerateRandomFilename(Extension)
                    Photo.save(os.path.join(StudentsBP.app.config['CERTIFICATE_PICS_FOLDER'], Filename))
                    EventData['CertificatePhotos'].append(url_for('static', filename=f'uploads/certificatepics/{Filename}'))
            EventData['CertificatePhotos'] = EventData['CertificatePhotos'][:5]  # Limit to 5 photos

            # Remove photos if requested
            remove_event_photos = request.form.getlist('remove_EventPhotos')
            remove_certificate_photos = request.form.getlist('remove_CertificatePhotos')

            EventData['EventPhotos'] = [photo for photo in EventData['EventPhotos'] if photo not in remove_event_photos]
            EventData['CertificatePhotos'] = [photo for photo in EventData['CertificatePhotos'] if photo not in remove_certificate_photos]

            # Remove files from server
            for photo in remove_event_photos + remove_certificate_photos:
                try:
                    # Convert URL to file path
                    file_path = os.path.join(StudentsBP.app.config['ROOT_PATH'], 'static', photo.split('/static/')[-1])
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        StudentsBP.app.logger.warning(f"File not found: {file_path}")
                except Exception as e:
                    StudentsBP.app.logger.error(f"Error removing file {file_path}: {str(e)}")
        else:
            EventData['ParticipatedWon'] = None
            EventData['Position'] = None
            EventData['PrizeAmount'] = None
            EventData['EventPhotos'] = []
            EventData['CertificatePhotos'] = []
       
        # Update data in MongoDB
        mongo.db.HackathonParticipations.update_one({"_id": ObjectId(id)}, {"$set": EventData})
        return redirect(url_for('students.Hackathons'))
   
    return render_template('students/Hackathons/Edit.html', hackathon=hackathon, RollNumber=RollNumber, name = name)

@StudentsBP.route('/hackathon/delete/<string:id>')
@LoggedInUser
def DeleteHackathon(id):
    mongo.db.HackathonParticipations.delete_one({"_id": ObjectId(id)})
    return redirect(url_for('students.Hackathons'))