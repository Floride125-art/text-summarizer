from flask import Flask,flash,render_template,request,g, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from flask_mail import Mail
import json, os, math
from datetime import datetime,timedelta,date
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, StringField, SelectField, DateField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from sqlalchemy.engine import Engine
from flask import send_file
from werkzeug.exceptions import BadRequestKeyError
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo
import base64
import imghdr
from io import BytesIO
from flask import Flask, jsonify, request
import base64
from io import BytesIO
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import random
import string
from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, flash
from sqlalchemy.exc import IntegrityError
import uuid


app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///test.db"
app.config['SQLALCHEMY_ECHO']=True
app.config["SECRET_KEY"] = "thisismysecretkey#"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
smtp_host = 'smtp.elasticemail.com'
smtp_port = 587
username = 'm.e.business.rw@gmail.com'
password = '124767AEB5F49F053968BF3E749E4389FCCD'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='injira'

#admin = Admin(app)

mail = Mail(app)

@event.listens_for(Engine,"connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
  cursor=dbapi_connection.cursor()
  cursor.execute("PRAGMA foreign_keys=ON")
  cursor.close()

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo

class RegistrationForm(FlaskForm):
  name = StringField('Full Name', validators=[DataRequired()])
  number=IntegerField('Phone Number', validators=[DataRequired()])
  email = StringField('Email', validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  role = StringField('Role', validators=[DataRequired()])
  submit = SubmitField('SignUp')    

class LoginForm(FlaskForm):
  
  email = StringField('Email',validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  remember = BooleanField('Remember Me')
  submit = SubmitField('Login')  

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

class MyUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    
class MentorRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)

class Picture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_data = db.Column(db.LargeBinary)

@app.route('/ikaze')
def ikaze():
    return render_template('ikaze.html')

@app.route('/ahabanza', methods=['GET', 'POST'])
def ahabanza():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')
            email = request.form.get('email')

            if not password:
                return 'Password is required!'

            if not role:
                return 'Role is required!'

            if not email:
                return 'Email is required!'

            if MyUser.query.filter_by(username=username).first():
                return 'Username already exists!'

            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                return 'Invalid email format!'

            if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):
                return 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character!'

            if role == 'mentor':
                new_mentor_request = MentorRequest(username=username, email=email)
                db.session.add(new_mentor_request)
                db.session.commit()
                
                return redirect(url_for('mentor_login'))

            new_user = MyUser(username=username, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('banza'))

        except BadRequestKeyError:
            return 'Invalid form data!'

    return render_template('ahabanza.html')


@app.route('/coursedashboard', methods=['GET', 'POST'])
def coursedashboard():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')
            email = request.form.get('email')

            if not password:
                return 'Password is required!'

            if not role:
                return 'Role is required!'

            if not email:
                return 'Email is required!'

            if MyUser.query.filter_by(username=username).first():
                return 'Username already exists!'

            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                return 'Invalid email format!'

            if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):
                return 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character!'

            if role == 'mentor':
                new_mentor_request = MentorRequest(username=username, email=email)
                db.session.add(new_mentor_request)
                db.session.commit()
                
                return redirect(url_for('mentor_login'))

            new_user = MyUser(username=username, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('banza'))

        except BadRequestKeyError:
            return 'Invalid form data!'

    return render_template('coursedashboard.html')

# Mentor login route
@app.route('/mentor/login', methods=['GET', 'POST'])
def mentor_login():
    if request.method == 'POST':
        username = request.form['username']
        
        mentor_request = MentorRequest.query.filter_by(username=username).first()
        if mentor_request:
            # Check if mentor's email is confirmed
            if mentor_request.email_confirmed:
                # Authenticate mentor and redirect to mentor dashboard
                mentor = MyUser.query.filter_by(username=username, role='mentor').first()
                if mentor:
                    session['user_id'] = mentor.id
                    return redirect(url_for('mentor_dashboard'))
                else:
                    return 'Invalid username or pass!'
            else:
                return 'Please wait for admin confirmation of your email!'
        else:
            return redirect(url_for('mentor_dashboard')) #attention

    return render_template('mentor_login.html')

@app.route('/mydashboard')
def mydashboard():
   usr=User.query.all()
   user_count = len(usr)
   std= StudentForm.query.all()
   packg=Package.query.all()
   hotl=Hotel.query.all()
   trans=Transport.query.all()
   cont=Contact.query.all()
   feedb=Feedback.query.all()
   paym=Payment.query.all()
   form_data = FormData.query.all()
   form_count = len(form_data)
   cont_count = len(cont)
   std_count = len(std)
   subscribe = Subscribe.query.all()
   teacher = OurTeacher.query.all()
   teacher_count = len(teacher)
   
   return render_template('admin_dashboard.html',  teacher_count=teacher_count, teacher= teacher, std_count= std_count, cont_count= cont_count, form_count=form_count, user_count=  user_count, usr=usr,std=std,packg=packg,hotl=hotl,cont=cont,feedb=feedb,paym=paym, trans=trans, form_data=form_data, subscribe=subscribe)
@app.route('/mentor_dashboard')
def mentor_dashboard():
    return render_template('mentor_dashboard.html')


@app.route('/myteacher')
def myteacher():
   usr=User.query.all()
   user_count = len(usr)
   std= StudentForm.query.all()
   packg=Package.query.all()
   hotl=Hotel.query.all()
   trans=Transport.query.all()
   cont=Contact.query.all()
   feedb=Feedback.query.all()
   paym=Payment.query.all()
   form_data = FormData.query.all()
   form_count = len(form_data)
   cont_count = len(cont)
   std_count = len(std)
   subscribe = Subscribe.query.all()
   teacher = OurTeacher.query.all()
   teacher_count = len(teacher)
   return render_template('viewfeedbacks.html',  teacher_count=teacher_count, teacher= teacher, std_count= std_count, cont_count= cont_count, form_count=form_count, user_count=  user_count, usr=usr,std=std,packg=packg,hotl=hotl,cont=cont,feedb=feedb,paym=paym, trans=trans, form_data=form_data, subscribe=subscribe)

@app.route('/mentor-confirmation')
def mentor_confirmation():
    # Render the mentor confirmation page
    return render_template('mentor_confirmation.html')

@app.route('/studentdashboard')
def studentdashboard():
    # Render the mentor confirmation page
    return render_template('student_dashboard.html')


@app.route('/reject_mentor/<int:user_id>')
def reject_mentor(user_id):
    user = User.query.get(user_id)

    if user and user.role == 'mentor':
        # Delete the user record for rejected mentor
        db.session.delete(user)
        db.session.commit()
        flash('Mentor rejected and removed successfully!', 'success')
    else:
        flash('User not found or not a mentor', 'error')

    return redirect(url_for('mydashboard'))


@app.route('/confirm_mentor/<int:user_id>')
def confirm_mentor(user_id):
    user = User.query.get(user_id)

    if user and user.role == 'mentor':
        # Update the user record to mark as confirmed
        user.confirmed = True
        db.session.commit()
        flash('Mentor confirmed successfully!', 'success')
    else:
        flash('User not found or not a mentor', 'error')

    return redirect(url_for('mydashboard'))



@app.route('/banza', methods=['GET', 'POST'])
def banza():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin@gmail.com' and password == 'admin123':
            session['user_id'] = 0  # Set a unique value for admin user
            return redirect(url_for('admin_dashboard'))
        
        myuser = MyUser.query.filter_by(username=username).first()
        if myuser and myuser.password == password:
            session['user_id'] = myuser.id
            return redirect(url_for('studentdashboard'))
        else:
            return 'Invalid username or password!'
    
    return render_template('banza.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        
        if user_id == 0:
            return render_template('admin_dashboard.html')
        
        myuser = MyUser.query.get(user_id)
        
        if myuser.role == 'student':
            return render_template('student_dashboard.html')
        elif myuser.role == 'mentor':
            return render_template('mentor_dashboard.html')
    
    return redirect(url_for('banza'))

@app.route('/sohoka')
def sohoka():
    session.pop('user_id', None)
    return redirect(url_for('banza'))




class User(UserMixin,db.Model):
    __tablename__="user"
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(64),index=True,nullable=False)
    number=db.Column(db.Integer, unique=True)
    email=db.Column(db.String(125),unique=True,nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    package=db.relationship('Package',backref=db.backref('pkgs'),lazy='dynamic')
    payment=db.relationship('Payment',backref=db.backref('pay'),lazy='dynamic')
    hotel=db.relationship('Hotel',backref=db.backref('hotl'),lazy='dynamic')
    transp=db.relationship('Transport',backref=db.backref('trans'),lazy='dynamic')
   

    def __repr__(self): 
            return '<User {}>'.format(self.username)
    def set_password(self, password):
            self.password_hash = generate_password_hash(password) 

    def check_password(self, password):
            return check_password_hash(self.password_hash, password)   
    
    def __repr__(self):
        return f"<User {self.email}>"

    


class Contact(db.Model):
    __tablename__="contact"
    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.String(80),nullable=False)
    name=db.Column(db.String(12), nullable=False)
    subject = db.Column(db.String(12), nullable=False)
    message= db.Column(db.String(320), nullable=False)
    date = db.Column(db.Integer, nullable=True)
    

class Feedback(db.Model):
    __tablename__="feedback"
    id = db.Column(db.Integer, primary_key=True)
    
    username=db.Column(db.String(64),index=True,unique=True,nullable=False)
    email = db.Column(db.String(80),nullable=False)
    scale=db.Column(db.String(64))
    rating=db.Column(db.String(64))
    feedback=db.Column(db.String(320))
    

class Package(db.Model):
    __tablename__="package"
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(80),nullable=False)
    package_name=db.Column(db.String(80), nullable=False)
    place=db.Column(db.String(80),nullable=False)
    numOfDays=db.Column(db.String(80), nullable=False)
    estimated_cost=db.Column(db.String(80), nullable=False)
    date_booked=db.Column(db.String(80),default = datetime.now,nullable=False)
    userid=db.Column(db.Integer, db.ForeignKey('user.id',onupdate="cascade"))
    




class Hotel(db.Model):
    __tablename__="hotel"
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(80),nullable=False)
    checkin_date=db.Column(db.String(80),default = datetime.date, nullable=False)
    checkout_date=db.Column(db.String(80),default = datetime.date, nullable=False)
    place=db.Column(db.String(80), nullable=False)
    cost=db.Column(db.String(80), nullable=False)
    star_type=db.Column(db.String(80), nullable=False)
    userid=db.Column(db.Integer,db.ForeignKey('user.id',onupdate="cascade"))


class Transport(db.Model):
    __tablename__="transport"
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(80),nullable=False)
    mode_of_transport=db.Column(db.String(80), nullable=False)
    trvcost=db.Column(db.String(80),nullable=False)
    start_date=db.Column(db.String(80),default = datetime.date, nullable=False)
    boarding_place=db.Column(db.String(80), nullable=False)
    place=db.Column(db.String(80), nullable=False)
    boarding_time=db.Column(db.String(80), nullable=False,default = datetime.time)
    userid=db.Column(db.Integer, db.ForeignKey('user.id',onupdate="cascade"))
    


class Payment(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(80),nullable=False)
    total_amount=db.Column(db.String(80),nullable=False)
    bookedpack=db.Column(db.String(80),nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('user.id',onupdate="cascade"))

class StudentForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    senderemail = db.Column(db.String(100), nullable=False)
    statustype = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    pnumber = db.Column(db.String(15), nullable=False, unique=True)
    address = db.Column(db.String(30), nullable=False)
    program = db.Column(db.String(20), nullable=False)
    education = db.Column(db.String(20), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    oleveldoc_filename = db.Column(db.String(100))
    aleveldoc_filename = db.Column(db.String(100))
    bachelor_filename = db.Column(db.String(100))
    masters_filename = db.Column(db.String(100))
    myid_filename = db.Column(db.String(100))
    mypassport_filename = db.Column(db.String(100))
    mycv_filename = db.Column(db.String(100))
    oleveldoc = db.Column(db.LargeBinary)
    aleveldoc = db.Column(db.LargeBinary)
    bachelor = db.Column(db.LargeBinary)
    masters= db.Column(db.LargeBinary) 
    myid= db.Column(db.LargeBinary)
    mypassport= db.Column(db.LargeBinary)
    mycv= db.Column(db.LargeBinary)
    status = db.Column(db.String(20))
   

   

    def __repr__(self):
        return f"StudentForm(id={self.id}, name='{self.name}', date_of_birth='{self.date_of_birth}', email='{self.email}', pnumber='{self.pnumber}', address='{self.address}', program='{self.program}', education='{self.education}', gender='{self.gender}', oleveldoc='{self.oleveldoc}', aleveldoc='{self.aleveldoc}', bachelor='{self.bachelor}' masters='{self.masters}', status='{self.status}', senderemail='{self.senderemail}', statustype='{self.statustype}', myid='{self.myid}', mycv='{self.mypassport}', mycv='{self.mycv}')"
class AdmissionLetter(db.Model):
      id = db.Column(db.Integer, primary_key=True)
      senderemail = db.Column(db.Text, nullable=False)
      filename = db.Column(db.String(100))
      admission_data = db.Column(db.LargeBinary)
      notes = db.Column(db.Text, nullable=True)
      student_id = db.Column(db.Integer, db.ForeignKey('student_form.id'), nullable=False)

class Admission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_data = db.Column(db.LargeBinary)
    
class OurTeacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name= db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    course = db.Column(db.Text, nullable=False)


class Work(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    duration = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_data = db.Column(db.LargeBinary)
   

class WorkAbroad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    mail = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    languages = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    duration = db.Column(db.String(100), nullable=False)
    cv_filename = db.Column(db.String(100))
    coverletter_filename = db.Column(db.String(100))
    picture_filename = db.Column(db.String(100))
    cv = db.Column(db.LargeBinary)
    coverletter = db.Column(db.LargeBinary)
    picture = db.Column(db.LargeBinary)
  

class Scholarship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
 
 
class StudentFeedbacks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    rname = db.Column(db.String(100), nullable=False)
    trimester = db.Column(db.String(100), nullable=False)
    stream = db.Column(db.String(100), nullable=False)
    sem7cse = db.Column(db.String(100), nullable=False)
    feedback = db.Column(db.Text, nullable=False)
 
class CourseList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    major = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)

class Bookingz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    price = db.Column(db.String(100), nullable=False)
    days = db.Column(db.String(100), nullable=False)
    place = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_data = db.Column(db.LargeBinary)

class Testimonies(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    images = db.Column(db.LargeBinary)

class Garelly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    images = db.Column(db.LargeBinary)

class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    images = db.Column(db.LargeBinary)

class FormData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    place2 = db.Column(db.String(100), nullable=False)
    date2 = db.Column(db.String(10), nullable=False)       

class Subscribe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False) 
    date = db.Column(db.Integer, nullable=True)

class InjiraForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Login')

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    testify = Testimonies.query.all()
    garelly = Garelly.query.all()
    uni = University.query.all()
    return render_template('index.html', testify = testify, garelly=garelly, uni=uni)

@app.route('/injirayo', methods=['GET', 'POST'])
def injirayo():
    form = InjiraForm(csrf_enabled=False)
    if form.validate_on_submit():
        email = form.email.data
        teacher = OurTeacher.query.filter_by(email=email).first()
        if teacher:
            session['teacher_id'] = teacher.id
            return jsonify({'status': 'success', 'message': 'Login Successful! Click ok'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid email! Please contact admin.'})

    return render_template('injirayo.html', form=form)

from flask import Flask, render_template, request, jsonify

@app.route('/injira', methods=['GET', 'POST'])
def injira():
    form = LoginForm(csrf_enabled=False)
    if form.validate_on_submit():
        if form.email.data == 'admin@gmail.com' and form.password.data == 'meconsultancy123':
            session['user'] = 'Admin'
           
            return redirect(url_for('mydashboard'))
        else:
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)
               
                return redirect(url_for('injira')) #changed welcome to injira
            else:
                
                return render_template('erroradminpage.html')
    return render_template('injira.html', form=form)

 

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)  

import smtplib
import secrets
import string

smtp_host = 'smtp.elasticemail.com'
smtp_port = 587
username = 'flo.tuyisenge@gmail.com'
password = 'DCCFC4389D435771FA8FDDDBA2E2F6CA8C71'

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(csrf_enabled=False)
    email = form.email.data
    if OurTeacher.query.filter_by(email=form.email.data).first():
        flash('Email is not valid or not from the database table.', 'error')
        password_characters = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(password_characters) for i in range(10))
        sender_email = username
        receiver_email = email
        message = f"""\
            
        Subject: Login Credentials
        Your login credentials:
        Email: {email}
        Password: {password}
        Click the following link to access the login form:
        {request.url_root}injira
        Please keep your password safe and do not share it with anyone."""
        with smtplib.SMTP("smtp.elasticemail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(username, password)
                smtp.sendmail(sender_email, receiver_email, message)
        flash('An email with login credentials has been sent to your email address.', 'success')
        return render_template('logthanks.html', form=form)
    else:
        flash('Email is not valid or not from the database table.', 'error')
    return render_template('register.html', form=form)

     
        



@app.route('/update_status/<int:student_id>/<status>')
def update_status(student_id, status):
    student_portal = StudentForm.query.get(student_id)
    if student_portal:
        student_portal.status = status
        db.session.commit()
        flash('Status updated successfully', 'success')
    else:
        flash('Student portal not found', 'error')

    return redirect(url_for('teacherportal'))


@app.route('/delete_card', methods=['DELETE'])
def delete_card():
    data = request.get_json()
    student_id = data['student_id']

    # Delete the card from the database
    student_portal = StudentForm.query.get(student_id)
    if student_portal:
        db.session.delete(student_portal)
        db.session.commit()

        response = {'success': True}
    else:
        response = {'success': False}

    return jsonify(response)


@app.route('/delete_cardi', methods=['DELETE'])
def delete_cardi():
    data = request.get_json()
    student_id = data['student_id']

    # Delete the card from the database
    student_portal = WorkAbroad.query.get(student_id)
    if student_portal:
        db.session.delete(student_portal)
        db.session.commit()

        response = {'success': True}
    else:
        response = {'success': False}

    return jsonify(response)



@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/consultancyedu')
def consultancyedu():
    return render_template('educonsultancy.html')



@app.route('/admissionPage')
def admnscholarship():
    return render_template('admissionPage.html')


@app.route('/addteacherPage')
def addteacherPage():
    return render_template('addteacher.html')


@app.route('/addcoursePage')
def addcoursePage():
    return render_template('addcourse.html')
@app.route('/workPage')
def workPage():
    return render_template('workadd.html')

@app.route('/bookingPage')
def bookingPage():
    return render_template('bookings.html')

@app.route('/testimoniesPage')
def testimoniesPage():
    return render_template('testimonies.html')

@app.route('/garellyPage')
def garellyPage():
    return render_template('addgarelly.html')

@app.route('/uniPage')
def uniPage():
    return render_template('adduni.html')

@app.route('/scholarships')
def scholarships():
    return render_template('scholarships.html')



@app.route('/admissionadd', methods=['POST'])
def add_admission():
    title = request.form['title']
    subtitle = request.form['subtitle']
    description = request.form['description']
    image = request.files['image']

    admission = Admission(title=title, subtitle=subtitle, description=description)
    admission.image_data = image.read()

    db.session.add(admission)
    db.session.commit()

    flash('Admission added successfully', 'success')
    return redirect('/admissionPage')


@app.route('/teacheradd', methods=['POST'])
def add_teacher():
    name = request.form['name']
    email = request.form['email']
    course = request.form['course']
   
    # Check if the email already exists in the database
    existing_teacher = OurTeacher.query.filter_by(email=email).first()
    if existing_teacher:
        flash('Email already exists. Please use a different email.', 'error')
        return redirect(url_for('addteacherPage'))
       
    # If email is unique, proceed to add the teacher
    teacher = OurTeacher(name=name, email=email, course=course)
    db.session.add(teacher)
    db.session.commit()

    flash('Teacher added successfully', 'success')
    return redirect('/mydashboard')

@app.route('/courseadd', methods=['POST'])
def add_course():
    if request.method == 'POST':
        course_name = request.form['course']
        code = request.form['code']
        semester = request.form['semester']
        major = request.form['major']
        category = request.form['category']
        
        new_course = CourseList(course=course_name, code=code, semester=semester, major=major, category=category)
        
        try:
            db.session.add(new_course)
            db.session.commit()
            flash('Course added successfully!', 'success')
        except:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
        finally:
            db.session.close()
            
        return redirect('/mydashboard')

    
@app.route('/workadd', methods=['POST'])
def add_work():
    title = request.form['title']
    subtitle = request.form['subtitle']
    location = request.form['location']
    duration = request.form['duration']
    description = request.form['description']
    image = request.files['image']

    admission = Work(title=title, subtitle=subtitle, location= location, duration= duration, description=description)
    admission.image_data = image.read()

    db.session.add(admission)
    db.session.commit()

    flash('Work added successfully', 'success')
    return redirect('/workPage')


@app.route('/workapplication', methods=['GET', 'POST'])
def add_workapp():
    name = request.form['name']
    mail = request.form['mail']
    phone = request.form['phone']
    titles = request.form['title']
    languages = request.form['languages']
    country = request.form['country']
    duration = request.form['duration']
    cv = request.files['cv']
    coverletter = request.files['coverletter']
    picture = request.files['picture']
    cv_filename = cv.filename if cv else None
    coverletter_filename = coverletter.filename if coverletter else None
    picture_filename = picture.filename if picture else None
    work = WorkAbroad(name=name, mail=mail, phone= phone, title=titles, languages=languages, country=country, duration=duration, cv_filename= cv_filename, coverletter_filename= coverletter_filename, picture_filename= picture_filename, cv=cv.read() if cv else None, coverletter = coverletter.read() if coverletter else None, picture = picture.read() if picture else None )
    db.session.add(work)
    db.session.commit()
    flash('Application Sent!', 'success')
    return redirect('/thankswork')



@app.route('/scholarshipadd', methods=['POST'])
def add_scholarship():
    title = request.form['title']
    description = request.form['description']
   

    admission = Scholarship(title=title, description=description)
   

    db.session.add(admission)
    db.session.commit()

    flash('Admission added successfully', 'success')
    return redirect('/scholarships')
@app.route('/bookingsadd', methods=['POST'])
def add_bookings():
    title = request.form['title']
    price = request.form['price']
    days = request.form['days']
    place = request.form['place']
    description = request.form['description']
    image = request.files['myimage']

    admission = Bookingz(title=title, price=price, place=place, days=days, description=description)
    admission.image_data = image.read()

    db.session.add(admission)
    db.session.commit()

    flash('Bookings added successfully', 'success')
    return redirect('/bookingPage')

@app.route('/testimoniesadd', methods=['POST'])
def add_testimonies():
    name = request.form['name']
    description = request.form['description']
    image = request.files['myimage']

    admission = Testimonies(name=name, description=description)
    admission.images= image.read()

    db.session.add(admission)
    db.session.commit()

    flash('Testimony added successfully', 'success')
    return redirect('/testimoniesPage')

@app.route('/garellyadd', methods=['POST'])
def add_garelly():
    name = request.form['name']
    image = request.files['myimage']

    garelly= Garelly(name=name)
    garelly.images= image.read()

    db.session.add(garelly)
    db.session.commit()

    flash('Photo added successfully', 'success')
    return redirect('/garellyPage')


@app.route('/uniadd', methods=['POST'])
def add_uni():
    name = request.form['name']
    image = request.files['myimage']

    garelly= University(name=name)
    garelly.images= image.read()

    db.session.add(garelly)
    db.session.commit()

    flash('Photo added successfully', 'success')
    return redirect('/uniPage')
@app.route('/admission', methods=['GET'])
def admission():
    admissions = Admission.query.all()
    return render_template('admission.html', admissions=admissions)


@app.route('/work', methods=['GET'])
def work():
    admissions = Work.query.all()
    return render_template('workabroad.html', admissions=admissions)

@app.route('/working', methods=['GET'])
def working():
    admissions = Work.query.all()
    return render_template('workupdate.html', admissions=admissions)

@app.route('/workedit', methods=['GET'])
def workedit():
    admissions = Work.query.all()
    return render_template('workedit.html', admissions=admissions)

@app.route('/myscholarship', methods=['GET'])
def myscholarship():
    scholarships = Scholarship.query.all()
    return render_template('myscholarship.html', scholarships=scholarships)

@app.route('/viewscholarship', methods=['GET'])
def viewscholarship():
    scholarships = Scholarship.query.all()
    return render_template('viewscholarship.html', scholarships=scholarships)

@app.route('/viewadmissions')
def viewadmissions():
     admissions = Admission.query.all()
     return render_template('addedadmission.html', admissions= admissions)

@app.route('/viewplaces')
def viewplaces():
     bookingz = Bookingz.query.all()
     return render_template('addedplaces.html', bookingz= bookingz)

@app.route('/thankswork')
def thanksworks():
     return render_template('workthanks.html')

@app.route('/viewtestify')
def viewtestify():
     testify = Testimonies.query.all()
     return render_template('addedtestimonies.html', testify= testify)

@app.route('/morebookings')
def morebookings():
     
     bookingz = Bookingz.query.all()
     return render_template('morebookings.html', bookingz  = bookingz )
import io
from flask import send_file, abort
@app.route('/admissions/image/<int:admission_id>')
def admission_image(admission_id):
    admission = Admission.query.get(admission_id)
    if admission:
        return app.response_class(admission.image_data, mimetype='image/jpeg')
    else:
        abort(404)

@app.route('/work/abroard/<int:admission_id>')
def work_image(admission_id):
    admission = Work.query.get(admission_id)
    if admission:
        return app.response_class(admission.image_data, mimetype='image/jpeg')
    else:
        abort(404)

@app.route('/bookings/image/<int:bookings_id>')
def bookings_image(bookings_id):
    bookings = Bookingz.query.get(bookings_id)
    if bookings:
        return app.response_class(bookings.image_data, mimetype='image/jpeg')
    else:
        abort(404)
@app.route('/testimonies/image/<int:testimonies_id>')
def testimonies_image(testimonies_id):
    testimonies = Testimonies.query.get(testimonies_id)
    if testimonies:
        return app.response_class(testimonies.images, mimetype='image/jpeg')
    else:
        abort(404)

@app.route('/garelly/image/<int:garelly_id>')
def garelly_image(garelly_id):
    garelly = Garelly.query.get(garelly_id)
    if garelly:
        return app.response_class(garelly.images, mimetype='image/jpeg')
    else:
        abort(404)


@app.route('/garelly/unive/<int:garelly_id>')
def unive_image(garelly_id):
    garelly = University.query.get(garelly_id)
    if garelly:
        return app.response_class(garelly.images, mimetype='image/jpeg')
    else:
        abort(404)
@app.route('/admissions/<int:admission_id>')
def view_admission(admission_id):
    admission = Admission.query.get(admission_id)
    return render_template('view_admission.html', admission=admission)


@app.route('/admissions/delete/<int:admission_id>')
def delete_admission(admission_id):
    admission = Admission.query.get(admission_id)
    db.session.delete(admission)
    db.session.commit()

    flash('Admission deleted successfully', 'success')
    return redirect('/admission')

@app.route('/welcome', methods=['GET', 'POST'])
@login_required
def welcome():
    if request.method == 'POST':
        name = request.form['name']
        date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date()
        senderemail = request.form['senderemail']
        statustype = request.form['statustype']
        email = request.form['email']
        pnumber = request.form['pnumber']
        address = request.form['address']
        program = request.form['program']
        education = request.form['education']
        gender = request.form['gender']
        oleveldoc = request.files['oleveldoc'] 
        aleveldoc = request.files['aleveldoc'] 
        bachelor = request.files['bachelor'] 
        masters = request.files['masters']
        myid = request.files['myid']
        mypassport = request.files['mypassport']
        mycv = request.files['mycv']
       

        # Perform form validation
        if not name or not email or not date_of_birth or not gender or not pnumber or not address or not program or not education or not statustype:
            return "Please fill out all fields."
        
      # Save the uploaded files
        oleveldoc_filename = oleveldoc.filename if oleveldoc else None
        aleveldoc_filename = aleveldoc.filename if aleveldoc else None
        bachelor_filename = bachelor.filename if bachelor else None
        masters_filename = masters.filename if masters else None
        myid_filename = myid.filename if masters else None
        mycv_filename = mycv.filename if masters else None
        mypassport_filename = mypassport.filename if masters else None
        

        studentportal = StudentForm(
            name=name,
            date_of_birth=date_of_birth,
            senderemail = senderemail,
            statustype = statustype,
            email=email,
            pnumber=pnumber,
            address=address,
            program=program,
            education=education,
            gender=gender,
            oleveldoc_filename=oleveldoc_filename,
            aleveldoc_filename=aleveldoc_filename,
            bachelor_filename=bachelor_filename,
            masters_filename=masters_filename,
            myid_filename=myid_filename,
            mypassport_filename=mypassport_filename,
            mycv_filename=mycv_filename,
            oleveldoc=oleveldoc.read() if oleveldoc else None,
            aleveldoc=aleveldoc.read() if aleveldoc else None,
            bachelor=bachelor.read() if bachelor else None,
            masters=masters.read() if masters else None,

        )
      
        db.session.add(studentportal)
        db.session.commit()

        return redirect('/thankyou')
    studentportals = StudentForm.query.all()
    admission_letters = {}

    logged_in_email = current_user.email if current_user.is_authenticated else None

    for student_portal in studentportals:
        
        if current_user.is_authenticated and student_portal.senderemail == logged_in_email:
            
            admission_letter = AdmissionLetter.query.filter_by(senderemail=student_portal.senderemail).first()
            if admission_letter:
                admission_letters[student_portal.senderemail] = admission_letter

    return render_template('welcome.html', studentportals= studentportals, admission_letters=admission_letters)

from email.message import EmailMessage
import smtplib



@app.route('/studfeed', methods=['GET', 'POST'])
def studfeed():
    if request.method == 'POST':
        name = request.form['name']
        rname = request.form['rname']
        trimester = request.form['trimester']
        stream = request.form['stream']
        sem7cse = request.form['sem7cse']
        feedback = request.form['feedback']
        
       

        # Perform form validation
        if not name or not rname or not  trimester or not stream or not sem7cse or not feedback:
            return "Please fill out all fields."
        
        studentdetails = StudentFeedbacks(
            name = name,
            rname = rname,
            trimester = trimester,
            stream =stream,
            sem7cse = sem7cse,
            feedback = feedback,

        )
      
        db.session.add(studentdetails)
        db.session.commit()

        return redirect('/thankyou')
    studentdetail = StudentForm.query.all()
    admission_letters = {}

    
    return render_template('garelly.html', admission_letters=admission_letters)

@app.route('/view_feedback/<course_code>', methods=['GET'])
def view_feedback(course_code):
    feedbacks = StudentFeedbacks.query.filter_by(sem7cse=course_code).all()
    feedbacksCount = len(feedbacks) 
    courses = CourseList.query.all()
  
    return render_template('feedback_view.html', courses=courses, feedbacksCount= feedbacksCount, feedbacks=feedbacks, course_code=course_code)


from flask import Flask, render_template, request, jsonify, redirect, url_for
from transformers import pipeline, AutoModelForSeq2SeqLM, AutoTokenizer
import os

model_name = "Daye34/student-feedback-summarizer"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSeq2SeqLM.from_pretrained(model_name)


@app.route('/view_individual_feedback/<int:feedback_id>/<course_code>', methods=['GET', 'POST'])
def view_individual_feedback(feedback_id, course_code):
    feedback = StudentFeedbacks.query.get(feedback_id)
    feedbacks = StudentFeedbacks.query.filter_by(sem7cse=course_code).all()
    feedbacks_count = len(feedbacks) 
   
    
    if request.method == 'POST':
        feedback_text = feedback.feedback
        inputs = tokenizer.encode("summarize: " + feedback_text, return_tensors="pt", max_length=512, truncation=True)
        summary_ids = model.generate(inputs, max_length=150, min_length=20, length_penalty=2.0, num_beams=4, early_stopping=True)
        summarized_text = tokenizer.decode(summary_ids[0], skip_special_tokens=True)
        return jsonify({"summary": summarized_text})
      

    if feedback:
        return render_template('summarizefeedback.html', feedback=feedback, course_code=course_code, feedbacks_count=feedbacks_count, feedbacks=feedbacks)
    else:
        return redirect(url_for('view_feedback', course_code=feedback.sem7cse, feedbacks_count=feedbacks_count, feedbacks=feedbacks))

@app.route('/send_email', methods=['POST'])
def send_email():
    recipient_email = request.form['recipient_email']
    student_id = request.form['student_id']

    try:
        studentportal = StudentForm.query.get(student_id)
        if not studentportal:
            return "Student not found", 404
        email_body = f"""
    Dear Sir/Madam,
    I hope this email finds you well. I would like to submit our aspirant information related to the admission application.
    Kindly, find the information of our aspirant below with attached documents.
        Applicant Name: {studentportal.name}
        Date of Birth: {studentportal.date_of_birth}
        Sender Email: {studentportal.senderemail}
        Status Type: {studentportal.statustype}
        Email: {studentportal.email}
        Phone number: {studentportal.pnumber}
        Address: {studentportal.address}
        Program: {studentportal.program}
        Education: {studentportal.education}
        Gender: {studentportal.gender}
        """
        msg = EmailMessage()
        msg['Subject'] = "Sending Aspirant information and documents"
        msg['From'] = 'm.e.business.rw@gmail.com'
        msg['To'] = recipient_email
        msg.set_content(email_body)

        if studentportal.oleveldoc:
            olevel_data = studentportal.oleveldoc 
            msg.add_attachment(olevel_data, maintype='application', subtype='octet-stream', filename=studentportal.oleveldoc_filename)

        if studentportal.aleveldoc:
            alevel_data = studentportal.aleveldoc 
            msg.add_attachment(alevel_data, maintype='application', subtype='octet-stream', filename=studentportal.aleveldoc_filename)

       
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)

    except Exception as e:
        return render_template('erroremail.html')

    return render_template('thanksemail.html')



@app.route('/compose_email', methods=['POST'])
def compose_email():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    place2 = request.form['place2']
    date2 = request.form['date2']

    form_data = FormData(name=name, email=email, phone=phone, place2=place2, date2=date2)
    db.session.add(form_data)
    db.session.commit()
    return redirect(url_for('visit'))

@app.route('/form2', methods=['GET', 'POST'])
def process_form2():
    if request.method == 'POST':
        place2 = request.form['place2']
        date2 = request.form['date2']
        return render_template('visit.html', place2=place2, date2=date2)

    return render_template('visit.html')
@app.route('/upload_admission_letter/<int:studentId>', methods=['POST'])
def upload_admission_letter(studentId):
    student = StudentForm.query.get(studentId)
    notes = request.form['notes']

    if not student:
        flash('Student not found') 

    admission_letter = request.files['admission_letter']

    if not admission_letter:
        return render_template('erroradmission.html')

    filename = secure_filename(admission_letter.filename)
    admission_letter_data = admission_letter.read()  

    admission = AdmissionLetter(
        senderemail=student.senderemail,
        filename=filename,
        admission_data=admission_letter_data,  
        student_id=studentId,
        notes = notes
    )
    db.session.add(admission)
    db.session.commit()

    return render_template('admissionthanksup.html')



from flask import send_file
from flask_login import current_user

@app.route('/download_admission/<int:admission_id>', methods=['GET'])
def download_admission(admission_id):
    admission = AdmissionLetter.query.get(admission_id)

    if not admission:
        return 'Admission letter not found', 404


    if current_user.email != admission.senderemail:
        return 'Unauthorized to view this admission letter', 403
    response = send_file(
        io.BytesIO(admission.admission_data),
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=admission.filename  
    )

    return response

from flask_login import current_user

@app.route('/addadmission', methods=['GET', 'POST'])
def addadmission():
    if request.method == 'POST':
        sender_email = request.form['sender_email']
        admission = request.files['admission']
        admission_filename = admission.filename if admission else None

        student_form = StudentForm.query.filter_by(senderemail=sender_email).first()
        if not student_form:
            return "Invalid sender email"

        admissionportal = AdmissionLetter(
            admission_filename=admission_filename,
            admission=admission.read() if admission else None,
            sender_email=sender_email,
            sender=student_form
        )
        db.session.add(admissionportal)
        db.session.commit()

        return redirect('/thanksletter')

    return render_template('teacherportal.html')


from flask import render_template, request
import base64
@app.template_filter('b64encode')
def b64encode_filter(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        pictures = request.files.getlist('pictures')
        picture_data_list = []

        for picture in pictures:
            picture_data = base64.b64encode(picture.read()).decode('utf-8')
            picture_data_list.append(picture_data)

        return render_template('profile.html', pictures=picture_data_list)

    return render_template('profile.html')

@app.route('/download_doc/<int:student_id>/<field>')
def download_doc(student_id, field):
    admission = AdmissionLetter.query.get(student_id)
    if not admission:
        return "document not found"
    
    doc_data = None
    docname = None
    doc_type = None
    if field == 'admission_data':
        doc_data = admission.admission_data
        docname = admission.filename
        doc_type = 'application/pdf' if docname.endswith('.pdf') else 'application/octet-stream'

    if not doc_data or not docname or not doc_type:
        abort(404)

    try:
        with open('temp_file', 'wb') as temp_file:
            temp_file.write(doc_data)
            
            return send_file('temp_file', mimetype=doc_type, as_attachment=True, download_name=docname)
    except Exception as e:
        print(f"Error while downloading file: {e}")
        abort(500)



@app.route('/download_admission_letter/<int:student_id>')
def download_admission_letter(student_id):
    admission = AdmissionLetter.query.get(student_id)
    if not admission:
        return "Admission letter not found"

    doc_data = admission.admission_data
    docname = admission.filename
    doc_type = 'application/pdf' if docname.endswith('.pdf') else 'application/octet-stream'

    if not doc_data:
        return "Admission letter not found"

    return send_file(doc_data, mimetype=doc_type, as_attachment=True)

@app.route('/download_document/<int:student_id>/<field>')
def download_document(student_id, field):
    studentportal = StudentForm.query.get(student_id)
   

    if not studentportal:
        return "Student not found"

    file_data = None
    filename = None
    content_type = None

    if field == 'oleveldoc':
        file_data = studentportal.oleveldoc
        filename = studentportal.oleveldoc_filename
        content_type = 'application/pdf' if filename.endswith('.pdf') else 'application/octet-stream'
    elif field == 'aleveldoc':
        file_data = studentportal.aleveldoc
        filename = studentportal.aleveldoc_filename
        content_type = 'application/pdf' if filename.endswith('.pdf') else 'application/octet-stream'
    elif field == 'bachelor':
        file_data = studentportal.bachelor
        filename = studentportal.bachelor_filename
        content_type = 'application/msword' if filename.endswith('.doc') else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' if filename.endswith('.docx') else 'application/octet-stream'
    elif field == 'masters':
        file_data = studentportal.masters
        filename = studentportal.masters_filename
        content_type = 'application/msword' if filename.endswith('.doc') else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' if filename.endswith('.docx') else 'application/octet-stream'


    if not file_data or not filename or not content_type:
        abort(404)  # Document not found, return a 404 error

    try:
        # Create a temporary file to store the file_data
        with open('temp_file', 'wb') as temp_file:
            temp_file.write(file_data)
            
            return send_file('temp_file', mimetype=content_type, as_attachment=True, download_name=filename)
    except Exception as e:
        # In case of any error, return a 500 error
        print(f"Error while downloading file: {e}")
        abort(500)

@app.route('/download_docs/<int:student_id>/<field>')
def download_docs(student_id, field):
    work = WorkAbroad.query.get(student_id)
   

    if not work:
        return "Student not found"

    file_data = None
    filename = None
    content_type = None

    if field == 'cv':
        file_data = work.cv
        filename = work.cv_filename
        content_type = 'application/pdf' if filename.endswith('.pdf') else 'application/octet-stream'
    elif field == 'coverletter':
        file_data = work.coverletter
        filename = work.coverletter_filename
        content_type = 'application/pdf' if filename.endswith('.pdf') else 'application/octet-stream'
    elif field == 'picture':
        file_data = work.picture
        filename = work.picture_filename
        content_type = 'application/msword' if filename.endswith('.doc') else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' if filename.endswith('.docx') else 'application/octet-stream'
  
    if not file_data or not filename or not content_type:
        abort(404)

    try:
        
        with open('temp_file', 'wb') as temp_file:
            temp_file.write(file_data)
            
            return send_file('temp_file', mimetype=content_type, as_attachment=True, download_name=filename)
    except Exception as e:
        
        print(f"Error while downloading file: {e}")
        abort(500)

@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

@app.route('/coursesview')
def coursesview():
    courses = CourseList.query.all()
    return render_template('coursesview.html', courses=courses)

@app.route('/admprof')
def admprof():
    return render_template('admnprof.html')

@app.route('/thanksletter')
def thanksletter():
    return render_template('thanksletter.html')

@app.route('/teacherportal',  methods=['GET', 'POST'])
def teacherportal():
    studentportals = StudentForm.query.all()
    student_status = {}
    for student_portal in studentportals:
        student_status[student_portal.id] = student_portal.status
    return render_template('teacherportal.html', studentportals = studentportals, student_status=student_status)


@app.route('/workportal',  methods=['GET', 'POST'])
def workportal():
    works = WorkAbroad.query.all()
    return render_template('workportal.html', works= works)


@app.route('/consultancy')
def consultancy():
    return render_template('consultancy.html')

@app.route('/visit')
def visit():
     bookingz = Bookingz.query.all()
     return render_template('visit.html', bookingz  = bookingz)

@app.route('/garelly')
def garelly(): 
     garelly = Garelly.query.all()
     return render_template('garelly.html', garelly=garelly)
@app.route('/viewgarelly')
def viewgarelly(): 
     garelly = Garelly.query.all()
     return render_template('garellyPage.html', garelly=garelly)

@app.route('/viewuni')
def viewuni(): 
     garelly = University.query.all()
     return render_template('viewuni.html', garelly=garelly)

@app.route('/studentnotify')
def studentnotify():
    studentportals = StudentForm.query.all()
    admission_letters = {}

    logged_in_email = current_user.email if current_user.is_authenticated else None

    for student_portal in studentportals:
        if current_user.is_authenticated and student_portal.senderemail == logged_in_email:
           
            admission_letter = AdmissionLetter.query.filter_by(senderemail=student_portal.senderemail).first()


            if admission_letter:
                admission_letters[student_portal.senderemail] = admission_letter

                notes = AdmissionLetter.query.filter_by(student_id=student_portal.id).first()
                student_portal.notes = notes.notes if notes else None



    return render_template('studentNotify.html', studentportals= studentportals, admission_letters=admission_letters)

@app.route('/dashboard')
def dashboard():
    usr=User.query.all()
    packg=Package.query.all()
    hotl=Hotel.query.all()
    trans=Transport.query.all()
    cont=Contact.query.all()
    feedb=Feedback.query.all()
    paym=Payment.query.all()
    return render_template('dashboard.html',usr=usr,packg=packg,hotl=hotl,cont=cont,feedb=feedb,paym=paym,trans=trans)

@app.route('/tables')
def tables():
    usr=User.query.all()
    std= StudentForm.query.all()
    packg=Package.query.all()
    hotl=Hotel.query.all()
    trans=Transport.query.all()
    cont=Contact.query.all()
    feedb=Feedback.query.all()
    paym=Payment.query.all()
    form_data = FormData.query.all()
    return render_template('tables.html',usr=usr,std=std,packg=packg,hotl=hotl,cont=cont,feedb=feedb,paym=paym, trans=trans, form_data=form_data)


@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

@app.route('/contact',methods=['GET','POST'])
def contact():
    if(request.method=='POST'):
            '''Add entry to the database'''
            mail = request.form.get('mail')
            name = request.form.get('name')
            subject = request.form.get('subject')
            message = request.form.get('message')
            try:
                contactme = Contact(mail = mail,name=name, subject = subject, message = message, date= datetime.now())
                db.session.add(contactme)
                db.session.commit()
                return render_template('thankscontact.html')
            except:
                return render_template('errorcontact.html')
    return render_template('contact.html')
        
@app.route('/workabroad',methods=['GET','POST'])
def workabroad():
    if(request.method=='POST'):
            '''Add entry to the database'''
            mail = request.form.get('mail')
            name = request.form.get('name')
            subject = request.form.get('subject')
            message = request.form.get('message')
            try:
                contactme = Contact(mail = mail,name=name, subject = subject, message = message, date= datetime.now())
                db.session.add(contactme)
                db.session.commit()
                flash('We will get in touch soon!')
            except:
                flash('Sorry Could not contact us...Please try again!! ')
    return render_template('work.html')

@app.route('/thankscontact')
def thankscontact():
    return render_template('thankscontact.html')
@app.route('/thanksemail')
def thanksemail():
    return render_template('thanksemail.html')

@app.route('/admissiontanks')
def admissionthanks():
    return render_template('admissionthanksup.html')

@app.route('/errorcontact')
def errorcontact():
    return render_template('errorcontact.html')
@app.route('/erroremail')
def erroremail():
    return render_template('erroremail.html')
@app.route('/errorregister')
def errorregister():
    return render_template('errorregister.html')
@app.route('/erroradmission')
def erroradmission():
    return render_template('erroradmission.html')
@app.route('/erroradmin')
def erroradmin():
    return render_template('erroradminpage.html')

@app.route('/usrcontact',methods=['GET','POST'])
def usrcontact():
    if(request.method=='POST'):
            '''Add entry to the database'''
            mail = request.form.get('mail')
            name = request.form.get('name')
            subject = request.form.get('subject')
            message = request.form.get('message')
            try:
                contactme = Contact(mail = mail,name=name, subject = subject, message = message, date= datetime.now())
                db.session.add(contactme)
                db.session.commit()
                flash('We will get in touch soon!')
            except:
                flash('Sorry Could not contact us...Please try again!! ')
    return render_template('usrcontact.html')
    


@app.route('/mntrcontact',methods=['GET','POST'])
def mntrcontact():
    if(request.method=='POST'):
            '''Add entry to the database'''
            mail = request.form.get('mail')
            name = request.form.get('name')
            subject = request.form.get('subject')
            message = request.form.get('message')
            try:
                contactme = Contact(mail = mail,name=name, subject = subject, message = message, date= datetime.now())
                db.session.add(contactme)
                db.session.commit()
                flash('We will get in touch soon!')
            except:
                flash('Sorry Could not contact us...Please try again!! ')
    return render_template('mntrcontact.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))    


@app.route('/delete/user/<int:id>')
def delete(id):
    if 'user' in session and session['user'] == 'Admin':
        deletePkg = OurTeacher.query.get_or_404(id)
        try:
            db.session.delete(deletePkg)
            db.session.commit()
            flash('Teacher Info successfully Deleted')
            return redirect('/mydashboard')
        except:
            return 'There was an issue to delete task'
    return 'Unauthorized access'

@app.route('/delete/student/<int:id>')
def deleteT(id):
    if ('user' in session and session['user'] == 'Admin'):
        deletetrns= StudentForm.query.get_or_404(id)
        try:
            db.session.delete(deletetrns)
            db.session.commit()
            flash('Student info successfully deleted ')
            return redirect('/mydashboard')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/contact/<int:id>')
def deleteC(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteCont=Contact.query.get_or_404(id)
        try:
            db.session.delete(deleteCont)
            db.session.commit()
            flash('Issue resolved')
            return redirect('/mydashboard')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/subscribe/<int:id>')
def deleteSub(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteCont=Subscribe.query.get_or_404(id)
        try:
            db.session.delete(deleteCont)
            db.session.commit()
            flash('Issue resolved')
            return redirect('/mydashboard')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/admission/<int:id>')
def deleteAdmission(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteAdm=Admission.query.get_or_404(id)
        try:
            db.session.delete(deleteAdm)
            db.session.commit()
            flash('Issue resolved')
            return redirect('/viewadmissions')
        except:
            return 'There was an issue to delete task'
        
@app.route('/delete/Bookings/<int:id>')
def deleteBookings(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteBookings=FormData.query.get_or_404(id)
        try:
            db.session.delete(deleteBookings)
            db.session.commit()
            flash('Bookings tansaction successfully deleted')
            return redirect('/mydashboard')
        except:
            return 'There was an issue to delete task'
        
@app.route('/delete/places/<int:id>')
def deletePlaces(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteplace=Bookingz.query.get_or_404(id)
        try:
            db.session.delete(deleteplace)
            db.session.commit()
            flash('place successfully deleted')
            return redirect('/viewplaces')
        except:
            return 'There was an issue to delete task'



@app.route('/delete/feedback/<int:id>')
def deleteF(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteFeed=Feedback.query.get_or_404(id)
        try:
            db.session.delete(deleteFeed)
            db.session.commit()
            flash('Feedback Taken into Consideration')
            return redirect('/dashboard')
            
        except:
            return 'There was an issue to delete task'

@app.route('/delete/testimonies/<int:id>')
def deleteTestify(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteTesti=Testimonies.query.get_or_404(id)
        try:
            db.session.delete(deleteTesti)
            db.session.commit()
            flash('Testimony successful Deleted')
            return redirect('/viewtestify')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/garelly/<int:id>')
def deleteGarelly(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteGar=Garelly.query.get_or_404(id)
        try:
            db.session.delete(deleteGar)
            db.session.commit()
            flash('Picture successful Deleted')
            return redirect('/viewgarelly')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/uni/<int:id>')
def deleteUni(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteGar=University.query.get_or_404(id)
        try:
            db.session.delete(deleteGar)
            db.session.commit()
            flash('Picture successful Deleted')
            return redirect('/viewuni')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/scholarship/<int:id>')
def deleteScholarship(id):
    if ('user' in session and session['user'] == 'Admin'):
        deleteGar=Scholarship.query.get_or_404(id)
        try:
            db.session.delete(deleteGar)
            db.session.commit()
            flash('Scholarship successful Deleted')
            return redirect('/viewscholarship')
        except:
            return 'There was an issue to delete task'


@app.route("/edit/student/<int:id>", methods = ['GET', 'POST'])
def editP(id):
    if ('user' in session and session['user'] == 'Admin'):
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            pnumber = request.form.get('pnumber')
            program = request.form.get('program')
            gender = request.form.get('gender')

            if id:
                post = StudentForm.query.filter(StudentForm.id ==id).first()
                post.name = name 
                post.email = email
                post.pnumber = pnumber
                post.program = program
                post.gender = gender
                db.session.commit()
                flash("Student Updated!")
                return redirect('/mydashboard')

        post = StudentForm.query.filter(StudentForm.id==id).first()
        return render_template('edit_student.html', post=post,id=id)

@app.route("/edit/user/<int:id>", methods = ['GET', 'POST'])
def editUser(id):
    if ('user' in session and session['user'] == 'Admin'):
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            course = request.form.get('course')
        
            if id:
                post = OurTeacher.query.filter(OurTeacher.id ==id).first()
                post.name = name 
                post.email = email
                post.course = course
                
                db.session.commit()
                flash("Teacher Updated!")
                return redirect('/mydashboard')

        post = OurTeacher.query.filter(OurTeacher.id==id).first()
        return render_template('edit_user.html', post=post,id=id)       

@app.route("/edit/details/<int:id>", methods = ['GET', 'POST'])
def editDetails(id):
    if ('user' in session and session['user'] == 'Admin'):
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            number = request.form.get('number')
            role = request.form.get('role')

            if id:
                post = User.query.filter(User.id ==id).first()
                post.name = name 
                post.number = number
                post.email = email
                post.role = role
                
                db.session.commit()
                flash("User Updated!")
                return redirect('/myprof')

        post = User.query.filter(User.id==id).first()
        return render_template('editmydetail.html', post=post,id=id)       

@app.route("/edit/bookings/<int:id>", methods = ['GET', 'POST'])
def editB(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            place2 = request.form.get('place2')
            date2 = request.form.get('date2')
            

            if id:
                post = FormData.query.filter(FormData.id == id).first()
                post.name = name
                post.email = email
                post.phone = phone
                post.place2 = place2
                post.date2 = date2
                db.session.commit()
                flash("Bookings Updated!")
                
                return redirect('/edit/bookings/'+str(id))
        post = FormData.query.filter(FormData.id ==id).first()
       
        return render_template('edit_bookings.html', post=post, id=id)


@app.route("/edit/admission/<int:id>", methods = ['GET', 'POST'])
def editTestimonies(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            title = request.form.get('title')
            subtitle = request.form.get('subtitle')
            description = request.form.get('description')

            if id:
                post = Admission.query.filter(Admission.id == id).first()
                post.title = title
                post.subtitle = subtitle
                post.description = description
                db.session.commit()
                flash("Admission Updated!")
                
                return redirect('/edit/admission/'+str(id))
        post = Admission.query.filter(Admission.id ==id).first()
       
        return render_template('edit_admission.html', post=post, id=id)


@app.route("/edit/work/<int:id>", methods = ['GET', 'POST'])
def editWork(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            title = request.form.get('title')
            location = request.form.get('location')
            duratiion = request.form.get('duration')
            subtitle = request.form.get('subtitle')
            description = request.form.get('description')

            if id:
                post = Work.query.filter(Work.id == id).first()
                post.title = title
                post.subtitle = subtitle
                post.location = location
                post.duration = duratiion
                post.description = description
                db.session.commit()
                flash("Work Updated!")
                
                return redirect('/edit/work/'+str(id))
        post = Work.query.filter(Work.id ==id).first()
       
        return render_template('workedit.html', post=post, id=id)
@app.route("/edit/scholarship/<int:id>", methods = ['GET', 'POST'])
def editScholarship(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')

            if id:
                post = Scholarship.query.filter(Scholarship.id == id).first()
                post.title = title
                post.description = description
                db.session.commit()
                flash("Scholarship Updated!")
                
                return redirect('/viewscholarship')
        post = Scholarship.query.filter(Scholarship.id ==id).first()
        return render_template('editscholarship.html', post=post, id=id)  
    
@app.route("/edit/places/<int:id>", methods = ['GET', 'POST'])
def editPlaces(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            title = request.form.get('title')
            price = request.form.get('price')
            days = request.form.get('days')
            place = request.form.get('place')
            description = request.form.get('description')
            if id:
                post = Bookingz.query.filter(Bookingz.id == id).first()
                post.title = title
                post.price = price
                post.days = days
                post.place = place
                post.description = description
                db.session.commit()
                flash("Places Updated!")
                
                return redirect('/edit/places/'+str(id))
        post = Bookingz.query.filter(Bookingz.id ==id).first()
       
        return render_template('edit_places.html', post=post, id=id)
    
@app.route("/edit/testimonies/<int:id>", methods = ['GET', 'POST'])
def editTestisfy(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            name = request.form.get('name')
            description = request.form.get('description')
            if id:
                post = Testimonies.query.filter(Testimonies.id == id).first()
                post.name = name
                post.description = description
                db.session.commit()
                flash("Testimonies Updated!")
                
                return redirect('/edit/testimonies/'+str(id))
        post = Testimonies.query.filter(Testimonies.id ==id).first()
       
        return render_template('edit_testimonies.html', post=post, id=id)
    
@app.route("/edit/contact/<int:id>", methods = ['GET', 'POST'])
def editContact(id):
    if ('user' in session and session['user'] == 'Admin'):
        
        if request.method == 'POST':
            name = request.form.get('name')
            mail = request.form.get('mail')
            subject = request.form.get('subject')
            message = request.form.get('message')
            if id:
                post = Contact.query.filter(Contact.id == id).first()
                post.name = name
                post.mail = mail
                post.subject= subject
                post.message = message
                db.session.commit()
                flash("Contact Updated!")
                
                return redirect('/edit/contact/'+str(id))
        post = Contact.query.filter(Contact.id ==id).first()
       
        return render_template('edit_contact.html', post=post, id=id)


@app.route("/edit/application/<int:id>", methods=['GET', 'POST'])
def editApplication(id):
    if 'user' in session and session['user'] == 'Admin':
        post = StudentForm.query.get(id)
        if post is None:
            return "Application not found."

        if request.method == 'POST':
            post.name = request.form['name']
            post.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date()
            post.statustype = request.form['statustype']
            post.email = request.form['email']
            post.pnumber = request.form['pnumber']
            post.address = request.form['address']
            post.program = request.form['program']
            post.education = request.form['education']
            post.gender = request.form['gender']

            # Handle file uploads (if new files are provided)
            file_fields = ['oleveldoc', 'aleveldoc', 'bachelor', 'masters', 'myid', 'mypassport', 'mycv']
            for field in file_fields:
                uploaded_file = request.files.get(field)
                if uploaded_file:
                    post_filename = secure_filename(uploaded_file.filename)
                    setattr(post, f'{field}_filename', post_filename)
                    setattr(post, field, uploaded_file.read())

            db.session.commit()
            flash("Application Updated!")
            return redirect('/myprof')

        return render_template('editapplication.html', post=post, id=id)


@app.route('/myprof')
def myprof():
    application_data = StudentForm.query.filter_by(senderemail=current_user.email).first()
    # Render the mentor confirmation page
    return render_template('myprof.html', application_data=application_data)

@app.route('/profiles')
def profiles():
    application_data = StudentForm.query.filter_by(senderemail=current_user.email).first()
    # Render the mentor confirmation page
    return render_template('profile.html', application_data=application_data)

@app.route('/delete/details/<int:id>')
def deleteDet(id):
    if ('user' in session and session['user'] == 'Admin'):
        deletetrns= StudentForm.query.get_or_404(id)
        try:
            db.session.delete(deletetrns)
            db.session.commit()
            flash('Student info successfully deleted ')
            return redirect('/myprof')
        except:
            return 'There was an issue to delete task'

@app.route('/delete/work/<int:id>')
def deleteWork(id):
    if ('user' in session and session['user'] == 'Admin'):
        deletework= Work.query.get_or_404(id)
        try:
            db.session.delete(deletework)
            db.session.commit()
            flash('Work info successfully deleted ')
            return redirect('/working')
        except:
            return 'There was an issue to delete task'




password_reset_tokens = {}

from flask import request, render_template, redirect, url_for, flash
import random
import string
from datetime import datetime, timedelta
app.config['MAIL_SERVER'] = 'smtp.elasticemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'm.e.business.rw@gmail.com'
app.config['MAIL_PASSWORD'] = '124767AEB5F49F053968BF3E749E4389FCCD'
app.config['MAIL_DEFAULT_SENDER'] = 'm.e.business.rw@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app)
password_reset_tokens = {}


import secrets

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = str(uuid.uuid4())
            password_reset_tokens[token] = {
                'email': email,
                'timestamp': datetime.utcnow(),
            }

            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Link", recipients=[email])
            msg.body = f"To reset your password, click the link below:\n\n{reset_link}"
            
            try:
                mail.send(msg)
                flash('If the provided email exists in our database, you will receive a password reset link.')
            except Exception as e:
                render_template('erroremail.html')

            return redirect(url_for('injira'))

        else:
            render_template('erroremail.html')

    return render_template('forgot_password.html', form=form)


from passlib.hash import sha256_crypt

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
       
        if token in password_reset_tokens:
          
            email = password_reset_tokens[token]['email']
           
            timestamp = password_reset_tokens[token]['timestamp']
            if datetime.utcnow() - timestamp < timedelta(hours=1):
                form = ResetPasswordForm()

                if form.validate_on_submit():
                   
                    new_password = form.new_password.data

                   
                    user = User.query.filter_by(email=email).first()
                    if user:
                      
                        hashed_password = sha256_crypt.hash(new_password)
                        user.set_password(new_password)  
                        db.session.commit()  

                       
                        password_reset_tokens.pop(token)

                        flash('Password reset successfully. You can now log in with your new password.')
                        print("Password reset successful. Redirecting to injira...")
                        return redirect(url_for('injira'))  

                    else:
                        flash('User not found.')
                        print("User not found.")

                return render_template('reset_password.html', form=form)

        flash('Invalid or expired password reset token. Please request a new password reset link.')
        print("Invalid or expired token. Redirecting to forgot_password...")
        return redirect(url_for('forgot_password'))  

    except Exception as e:
       
        flash(f"An error occurred: {e}")
        print(f"An error occurred: {e}")

    print("Redirecting to injira...")
    return redirect(url_for('injira'))  

from flask import Flask, render_template, request, flash, redirect, url_for
from flask_wtf.csrf import CSRFProtect

subscribed_emails = []

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if request.method == 'POST':
        email = Subscribe.query.all()

       
        if email in subscribed_emails:
            flash('You have already subscribed with this email.')
        else:
         
            subscribed_emails.append(email)
            flash('Subscription successful. Thank you for subscribing!')

       
            message = Message(subject='Subscribed on our News Letter', recipients=[email])
            message.body = f'thank you for subscribing to our news letter'
            try: 
                mail.send(message)
                print("Email sent successfully!")
            except Exception as e:
                print(f"Error sending email: {e}")

    return redirect(url_for('home', email=email))

@app.route('/subscribers',methods=['GET','POST'])
def subscribers():
    if(request.method=='POST'):
            '''Add entry to the database'''
            email = request.form.get('email')
            try:
                subscribe = Subscribe(email = email, date= datetime.now())
                db.session.add(subscribe)
                db.session.commit()
                flash('Thanks for subscribing, we will come back to you soon!')
            except:
                flash('Sorry Could subscribe...Please try again!! ')
    return render_template('index.html')

if __name__=="__main__":
    app.run(debug=True)
    