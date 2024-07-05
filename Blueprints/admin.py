from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, Blueprint
from dotenv import load_dotenv
import os
from flask_pymongo import PyMongo
from functools import wraps
from datetime import datetime, timedelta, timezone
from Modules import AES256, SHA256, Mail
import re
import secrets
import string
from db import mongo

AdminBP = Blueprint('admin', __name__)

