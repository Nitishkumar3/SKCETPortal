from flask import Flask, send_from_directory, render_template, session
from db import mongo
from Blueprints.students import StudentsBP
from Blueprints.staffs import StaffsBP
from Blueprints.admin import AdminBP
from dotenv import load_dotenv
import os

load_dotenv()
MONGO_URI = os.getenv('MongoURI')

app = Flask(__name__)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

app.config['MONGO_URI'] = MONGO_URI
mongo.init_app(app)

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
EVENT_PICS_FOLDER = os.path.join(UPLOAD_FOLDER, 'eventpics')
CERTIFICATE_PICS_FOLDER = os.path.join(UPLOAD_FOLDER, 'certificatepics')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(EVENT_PICS_FOLDER, exist_ok=True)
os.makedirs(CERTIFICATE_PICS_FOLDER, exist_ok=True)

app.register_blueprint(StudentsBP, url_prefix='/', mongo=mongo)
app.register_blueprint(StaffsBP, url_prefix='/staff', mongo=mongo)
app.register_blueprint(AdminBP, url_prefix='/admin', mongo=mongo)

@app.route('/assets/<path:filename>')
def Static(filename):
    return send_from_directory('Assets', filename)

@app.route('/')
def Index():
    return render_template("Index.html")

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")