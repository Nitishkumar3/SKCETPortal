from flask import Flask, send_from_directory, render_template, session
from db import mongo
from Blueprints.students import StudentsBP
from Blueprints.staffs import StaffsBP
from Blueprints.admin import AdminBP
from dotenv import load_dotenv
import os
import random
from datetime import datetime

load_dotenv()
MONGO_URI = os.getenv('MongoURI')

app = Flask(__name__)
app.jinja_env.globals.update(enumerate=enumerate, int=int, random=random.choice)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

app.config['MONGO_URI'] = MONGO_URI
mongo.init_app(app)

UploadFolder = 'static/uploads'

app.config['UPLOAD_FOLDER'] = UploadFolder
app.config['EVENT_PICS_FOLDER'] = os.path.join(UploadFolder, 'eventpics')
app.config['CERTIFICATE_PICS_FOLDER'] = os.path.join(UploadFolder, 'certificatepics')
app.config['ROOT_PATH'] = app.root_path
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}

os.makedirs(os.path.join(UploadFolder, 'eventpics'), exist_ok=True)
os.makedirs(os.path.join(UploadFolder, 'certificatepics'), exist_ok=True)

@app.template_filter('time_since')
def time_since_filter(dt):
    now = datetime.now()
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365} years ago"
    elif diff.days > 30:
        return f"{diff.days // 30} months ago"
    elif diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60} minutes ago"
    else:
        return f"{diff.seconds} seconds ago"
    

StudentsBP.app = app

app.register_blueprint(StudentsBP, url_prefix='/')
app.register_blueprint(StaffsBP, url_prefix='/staff', mongo=mongo)
app.register_blueprint(AdminBP, url_prefix='/admin', mongo=mongo)

@app.route('/assets/<path:filename>')
def Static(filename):
    return send_from_directory('Assets', filename)

@app.route('/')
def Index():
    IsLoggedIn = False
    if 'SessionKey' in session and 'RollNumber' in session:
        IsLoggedIn = True
    return render_template("Index.html", IsLoggedIn=IsLoggedIn)

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")