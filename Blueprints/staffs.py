from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, Blueprint, jsonify
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
            return redirect(url_for('staffs.Dashboard'))
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
    VerifiedStatus = mongo.db.StaffVerification.find_one({'RollNumber': UserName, 'Verified': True})
    return VerifiedStatus is not None

# def PasswordResetMail(UserName, email, ResetKey):
#     subject = "SKCET - Password Reset"
#     link = "http://localhost:5000/staff/resetkey/" + str(ResetKey)
#     body = "Password Reset Code: " + str(ResetKey) + f" {link}"
#     if Mail.SendMail(subject, body, email):
#         currenttime = datetime.utcnow()
#         mongo.db.PasswordReset.insert_one({'UserName': UserName, 'ResetKey': ResetKey, 'CreatedAt': currenttime, 'ExpirationTime': currenttime + timedelta(hours=6)})
#         mongo.db.PasswordReset.create_index('ExpirationTime', expireAfterSeconds=0)


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

@StaffsBP.route('/')
@LoggedInUser
def Index():
    return redirect(url_for('staffs.Index'))

@StaffsBP.route('/dashboard')
@LoggedInUser
def Dashboard():
    UserName = session['UserName']
    user = mongo.db.Staffs.find_one({'UserName': UserName})
    name = user["first_name"]
    return render_template("staffs/Dashboard.html", name=name, schedule=schedule, articles=articles, announcements=announcements)

@StaffsBP.route('/studentdetails')
@LoggedInUser
def StudentDetails():
    UserName = session['UserName']
    user = mongo.db.Staffs.find_one({'UserName': UserName})
    students = mongo.db.StudentDetails.find({'degree': user["Degree"], "department": user["Department"]})
    students = list(students)
    name = user["first_name"]
    return render_template("staffs/StudentDetails/Index.html", students=students, name=name)

@StaffsBP.route('/hackathondetails')
@LoggedInUser
def HackathonDetails():
    UserName = session['UserName']
    user = mongo.db.Staffs.find_one({'UserName': UserName})
    name = user["first_name"]
    Department = ToShortCode(user["Degree"], user["Department"])
    HackathonDetails = list(mongo.db.HackathonParticipations.find({'Department': Department}))

    for index, item in enumerate(HackathonDetails, start=1):
        item['sno'] = index

    for result in HackathonDetails:
        if '_id' in result:
            result['_id'] = str(result['_id'])

    return render_template("staffs/HackathonDetails/Index.html", hackathons=HackathonDetails, name=name)

@StaffsBP.route('/timetable')
@LoggedInUser
def Timetable():
    UserName = session['UserName']
    user = mongo.db.Staffs.find_one({'UserName': UserName})
    name = user["first_name"]

    return render_template('staffs/Timetable/Index.html', name=name, schedule=schedule)

from flask import send_file, request, jsonify
from io import BytesIO
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Image, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import inch

# # Register Calibri font (make sure you have the Calibri.ttf file)
# pdfmetrics.registerFont(TTFont('Calibri', 'Calibri.ttf'))
# pdfmetrics.registerFont(TTFont('Calibri-Bold', 'Calibri-Bold.ttf'))
try:
    pdfmetrics.registerFont(TTFont('Calibri', 'Calibri.ttf'))
    pdfmetrics.registerFont(TTFont('Calibri-Bold', 'Calibri-Bold.ttf'))
    default_font = 'Calibri'
    default_bold_font = 'Calibri-Bold'
except Exception as e:
    print(f"Error registering Calibri fonts: {str(e)}")
    try:
        pdfmetrics.registerFont(TTFont('TimesNewRoman', 'times-ro.ttf'))
        pdfmetrics.registerFont(TTFont('TimesNewRoman-Bold', 'times-new-roman-grassetto.ttf'))
        default_font = 'TimesNewRoman'
        default_bold_font = 'TimesNewRoman-Bold'
    except Exception as e:
        print(f"Error registering Times New Roman fonts: {str(e)}")
        default_font = 'Helvetica'
        default_bold_font = 'Helvetica-Bold'
    
@StaffsBP.route('/ep', methods=['POST'])
@LoggedInUser
def receive_json():
    try:
        data = request.json
        # print("Data received:", data)
        
        if not data:
            return jsonify({"error": "No data received"}), 400
        
        roll_numbers = data.get('rollNumbers', [])
        columns = data.get('columns', [])

        
        if not roll_numbers or not columns:
            return jsonify({"error": "Invalid data received: missing roll numbers or columns"}), 400
        
        columns = [col for col in columns if col]
        if not columns:
            return jsonify({"error": "No valid columns provided"}), 400



        column_map = {
            'Roll Number': 'RollNumber',
            'First Name': 'first_name',
            'College Email': 'Email',
            'Aadhaar Number': 'aadhaar_number',
            'Account Number': 'account_number',
            'Admission Mode': 'admission_mode',
            'Annual Income': 'annual_income',
            'Bank Account Name': 'bank_account_name',
            'Bank Name': 'bank_name',
            'Batch': 'batch',
            'Branch': 'branch',
            'City': 'city',
            'Communication Address': 'communication_address',
            'Communication City': 'communication_city',
            'Communication Postal Code': 'communication_postal_code',
            'Communication State': 'communication_state',
            'Community': 'community',
            'Country Name': 'country_name',
            'Course Type': 'course_type',
            'Date of Admission': 'date_of_admission',
            'Degree': 'degree',
            'Department': 'department',
            'Differently Abled': 'differently_abled',
            'Disability Percentage': 'disability_percentage',
            'Disability Type': 'disability_type',
            'Date of Birth': 'dob',
            'EMIS Number': 'emis_number',
            'Father Mobile': 'father_mobile',
            'Father Name': 'father_name',
            'Father Occupation': 'father_occupation',
            'First Graduate': 'first_graduate',
            'Gender': 'gender',
            'Guardian Mobile': 'guardian_mobile',
            'Guardian Name': 'guardian_name',
            'Health Issues': 'health_issues',
            'Health Issues Details': 'health_issues_details',
            'Hostel Type': 'hostel_type',
            'Hosteller': 'hosteller',
            'IFSC Code': 'ifsc_code',
            'Last Name': 'last_name',
            'Lateral Entry': 'lateral_entry',
            'Mobile Number': 'mobile_number',
            'Mother Mobile': 'mother_mobile',
            'Mother Name': 'mother_name',
            'Mother Occupation': 'mother_occupation',
            'Nationality': 'nationality',
            'Orphan': 'orphan',
            'PAN Number': 'pan_number',
            'Permanent Address': 'permanent_address',
            'Personal Email': 'personal_email',
            'PG Address': 'pg_address',
            'Postal Code': 'postal_code',
            'Quota': 'quota',
            'Religion': 'religion',
            'Section': 'section',
            'State': 'state',
            'Status': 'status',
            'Sub Caste': 'sub_caste',
            'TNEA Application Number': 'tnea_application_number',
            'UDID': 'udid',
            'Voter ID': 'voter_id',
            'Year': 'year'
        }

        converted_columns = list(map(lambda col: column_map[col], columns))
        # print("Converted columns:", converted_columns)
        columns = converted_columns

        query = {"RollNumber": {"$in": roll_numbers}}

        # results = mongo.db.StudentDetails.find(query)
        # results = list(results)
        try:
            results = mongo.db.StudentDetails.find(query)
            results = list(results)
            # print(f"Found {len(results)} results")
        except Exception as e:
            print(f"Error querying MongoDB: {str(e)}")
            return jsonify({"error": f"Database error: {str(e)}"}), 500

        if not results:
            return jsonify({"error": "No data found for the given roll numbers"}), 404

        filtered_results = []
        for student in results:
            filtered_student = {key: student[key] for key in converted_columns if key in student}
            filtered_results.append(filtered_student)

        # print("Filtered results:", filtered_results)

        reverse_column_map = {v: k for k, v in column_map.items()}

        reversed_filtered_results = [
            {reverse_column_map[key]: value for key, value in item.items() if key in reverse_column_map}
            for item in filtered_results
        ]

        df = pd.DataFrame(reversed_filtered_results)
        df.insert(0, 'S.No', range(1, len(df) + 1))

        buffer = BytesIO()

        # Increase top margin to accommodate the header logo
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=20, leftMargin=20, topMargin=80, bottomMargin=20)

        elements = []

        # Function to estimate column widths
        def estimate_col_width(col_data):
            max_width = max(len(str(item)) for item in col_data)
            return max(max_width * 6, 60)  # Adjust multiplier as needed

        # Estimate column widths
        estimated_widths = [estimate_col_width(df[col]) for col in df.columns]

        # Prepare data for table
        data = [df.columns.tolist()] + df.values.tolist()

        # Calculate how many columns can fit on one page
        available_width = doc.width - 40  # Subtracting margins
        columns_per_page = []
        current_page_width = 0
        current_page_columns = 0

        for width in estimated_widths:
            if current_page_width + width > available_width:
                columns_per_page.append(current_page_columns)
                current_page_width = width
                current_page_columns = 1
            else:
                current_page_width += width
                current_page_columns += 1

        if current_page_columns > 0:
            columns_per_page.append(current_page_columns)

        # Create tables for each page
        start_col = 0
        for page_columns in columns_per_page:
            end_col = start_col + page_columns
            sub_data = [row[start_col:end_col] for row in data]
            sub_widths = estimated_widths[start_col:end_col]

            # Scale widths to fit page
            scale_factor = available_width / sum(sub_widths)
            sub_widths = [width * scale_factor for width in sub_widths]

            table = Table(sub_data, colWidths=sub_widths)

            style = TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Calibri'),
                ('FONT', (0, 0), (-1, 0), 'Calibri-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True),
            ])
            table.setStyle(style)

            elements.append(table)

            if end_col < len(df.columns):
                elements.append(PageBreak())

            start_col = end_col

        # Build the PDF with custom page layout
        def add_header_and_page_number(canvas, doc):
            canvas.saveState()

            # Add header image
            # header_image_path = 'logo.jpg'  # Replace with actual path
            # img = Image(header_image_path)
            # img_width = doc.width * 0.5
            # img.drawWidth = img_width
            # img.drawHeight = img.drawWidth * img.imageHeight / img.imageWidth
            # img.drawOn(canvas, (doc.width - img_width) / 2 + doc.leftMargin, doc.height + doc.topMargin - img.drawHeight)
            
            header_image_path = 'logo.jpg'
            try:
                img = Image(header_image_path)
                img_width = doc.width * 0.5
                img.drawWidth = img_width
                img.drawHeight = img.drawWidth * img.imageHeight / img.imageWidth
                img.drawOn(canvas, (doc.width - img_width) / 2 + doc.leftMargin, doc.height + doc.topMargin - img.drawHeight)
            except Exception as e:
                print(f"Error loading header image: {str(e)}")
                # Optionally, continue without the image
                # You can add a text header instead, or just skip the header entirely
                canvas.setFont(default_font, 16)
                canvas.drawString(doc.leftMargin, doc.height + doc.topMargin - 30, "Student Details Report")


            # Add page number
            page_num = canvas.getPageNumber()
            text = f"Page {page_num}"
            canvas.setFont(default_font, 16)
            canvas.drawRightString(doc.width + doc.rightMargin, 0.5 * inch, text)

            canvas.restoreState()

        # doc.build(elements, onFirstPage=add_header_and_page_number, onLaterPages=add_header_and_page_number)
        try:
            doc.build(elements, onFirstPage=add_header_and_page_number, onLaterPages=add_header_and_page_number)
        except Exception as e:
            print(f"Error building PDF: {str(e)}")
            return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500
        buffer.seek(0)

        return send_file(buffer, as_attachment=True, download_name="exported_data.pdf", mimetype="application/pdf")
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in receive_json: {str(e)}\n{error_details}")
        return jsonify({"error": str(e), "details": error_details}), 500

@StaffsBP.route('/verifyaccount/<RollNumber>', methods=['GET', 'POST'])
@NotLoggedInUser
def VerifyAccount(RollNumber):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = mongo.db.StaffVerification.find_one({'RollNumber': RollNumber, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('staffs.Login'))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            mongo.db.StaffVerification.update_one({'RollNumber': RollNumber}, {'$set': {'Verified': True}})
            return redirect(url_for('staffs.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('staffs.VerifyAccount', RollNumber=RollNumber))

    return render_template('staffs/VerifyAccount.html', RollNumber=RollNumber)






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
        
        if not IsUserVerified(user["RollNumber"]):
            flash('User not verified! Please complete the OTP verification', 'error')
            return redirect(url_for('staffs.VerifyAccount', RollNumber=user["Email"].split("@")[0]))

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

            return redirect(url_for('staffs.Dashboard'))
        else:
            flash('Invalid Login or password', 'error')
    return render_template('staffs/Login.html')

# @StaffsBP.route('/forgotpassword', methods=['GET', 'POST'])
# @NotLoggedInUser
# def ForgotPassword():
#     if request.method == 'POST':
#         login = request.form['login']

#         if "@" in login:
#             user = mongo.db.Staffs.find_one({'Email': login})
#         else:
#             user = mongo.db.Staffs.find_one({'UserName': login})

#         if not user:
#             flash('Invalid Username or Email ID', 'error')
#             return redirect(url_for('staffs.ForgotPassword'))

#         ResetKey = AES256.GenerateRandomString(32)
#         PasswordResetMail(user["UserName"], user["Email"], ResetKey)

#         flash('A Password Reset Link has been sent to your Email! Please check your Inbox and Follow the Instructions', 'info')
#     return render_template('staffs/ForgotPassword.html')

# @StaffsBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
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
#             return redirect(url_for('staffs.ResetPassword', ResetKey=ResetKey))
        
#         user = mongo.db.Staffs.find_one({'UserName': ResetData['UserName']})

#         passwordH = SHA256.HashPassword(NewPassword, user["UserName"])

#         mongo.db.Staffs.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordH}})

#         mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
#         flash('Password reset successful. Try Loggin in.', 'info')
#         return redirect(url_for('staffs.Login'))
#     return render_template('staffs/ResetPassword.html', ResetKey=ResetKey)

from flask import flash, redirect, url_for, render_template, request
from Modules.Mail import SendMail
from Modules import AES256, SHA256
import re
from datetime import datetime, timedelta

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
        
        # Store the reset key in the database
        mongo.db.PasswordReset.insert_one({
            'UserName': user['UserName'],
            'ResetKey': ResetKey,
            'CreatedAt': datetime.utcnow(),
            'ExpirationTime': datetime.utcnow() + timedelta(hours=24)
        })
        mongo.db.PasswordReset.create_index('ExpirationTime', expireAfterSeconds=0)

        # Send password reset email
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
            return redirect(url_for('staffs.ForgotPassword'))
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('staffs.ResetPassword', ResetKey=ResetKey))
        
        user = mongo.db.Staffs.find_one({'UserName': ResetData['UserName']})

        passwordH = SHA256.HashPassword(NewPassword, user["UserName"])

        mongo.db.Staffs.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordH}})

        mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
        # Send password reset confirmation email
        PasswordResetConfirmationMail(user["Email"])
        
        flash('Password reset successful. You can now log in with your new password.', 'success')
        return redirect(url_for('staffs.Login'))
    return render_template('staffs/ResetPassword.html', ResetKey=ResetKey)

def PasswordResetMail(username, email, reset_key):
    subject = "Reset Your Password - SKCET Staff Portal"
    reset_link = url_for('staffs.ResetPassword', ResetKey=reset_key, _external=True)
    
    # Plain text version
    plain_text = f"""
    Reset Your Password - SKCET Staff Portal

    Dear {username},

    We received a request to reset your password. Use the link below to set up a new password for your account:

    {reset_link}

    If you didn't request this, you can safely ignore this email.

    This password reset link will expire in 24 hours.

    SKCET Staff Support Team
    """

    # HTML version
    html_content = render_template('email/StaffPasswordResetEmail.html', username=username, reset_link=reset_link)

    SendMail(subject, plain_text, email, html_content)

def PasswordResetConfirmationMail(email):
    subject = "Password Reset Successful - SKCET Staff Portal"
    login_link = url_for('staffs.Login', _external=True)
    
    # Plain text version
    plain_text = f"""
    Password Reset Successful - SKCET Staff Portal

    Your password has been successfully reset.

    If you did not perform this action, please contact our support team immediately.

    Log in to your account: {login_link}

    SKCET Staff Support Team
    """

    # HTML version
    html_content = render_template('email/StaffResetPasswordConfirmationEmail.html', login_link=login_link)

    SendMail(subject, plain_text, email, html_content)



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
    return redirect(url_for('staffs.Dashboard'))