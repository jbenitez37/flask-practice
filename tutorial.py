from base64 import encode
from email import message
from ensurepip import bootstrap
from sqlite3 import Timestamp
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy #used this to create userdata base so you can sign in and out of the site
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail
from flask_mail import Message 
from flask import request
from datetime import datetime
import time 
import sys 
sys.path.append('/Users/josue/Desktop/Code/blue-sky')
import remind_bot as rb
import os
from celery import Celery
import threading
from flask import copy_current_request_context
########################## Configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

os.environ.setdefault('FORKED_BY_MULTIPROCESSING', '1')
celery = Celery(app.name, broker='redis://localhost:6379/0')

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'reminderapp480@gmail.com'
app.config['MAIL_PASSWORD'] = 'slpmiwsrcrvqyhal' #password for reminderapp480@gmail.com to bypass security and send email
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

###################################

class User(UserMixin, db.Model):
    ''' 
    Creates a data-model called User, with User authentication fields 
        
    Parameters
    ----------
    id: 
    db.Column(db.Integer, primary_key=True)
    username: preffered username
    email: email of User
    password: preferred password

    '''
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True) #the db.String() refers to the maximum length of characters 
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    '''
    Creates a data-model called LoginForm, with login fields

    Parameters:
    username: str
    password: str
    remember: boolean
    '''
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/Overview')
def Overview():
    return '<h1>Hello, After entering your phone number and carrier, simply enter the reminder you want and the time of your choosing. Then a message will be sent to your phone at the specified time.</h1>'
    
@app.route("/Remind")     #using flask-mail this sends a message
@login_required
def Reminder():
    return render_template('reminder.html')


@app.route('/result', methods=['GET', 'POST']) 
def result():
    if request.method == "POST":
        #r =  rb.Remind(request.form.get("Subject"), request.form.get("Body"), request.form.get("datetime"))
        subject = request.form.get("Subject")
        body = request.form.get("Body") 
        recipient= request.form.get("Number")
        print(request.form)
        send_time = datetime.strptime(request.form.get("datetime"), "%Y-%m-%dT%H:%M")
        message = Message(subject=subject, recipients=[recipient], body=body, sender=app.config['MAIL_USERNAME'])
        send_async(send_time, message)
        return render_template('result.html', result="cool it works :)")
    else:
        return render_template('result.html', result="Failure :(")

def test_func(message):
    print("running...")
    with open("test.txt", "w") as f:
        f.write(str(message))


def test_sender(message):
    sender = threading.Thread(name='sender_test', target=test_func, args=(message,))
    sender.start()

        
def send_async(send_time, message):
       
    @copy_current_request_context
    def send_message(message):
        print("sending...")
        now = datetime.now()
        print(f"now: {now}, send time: {send_time}, now <= sendtime: {now <= send_time}")
        while now <= send_time:
            print(f"now: {now}, send time: {send_time}, now <= sendtime: {now <= send_time}") 
            now = datetime.now()
            time.sleep(1)
        mail.send(message)
    print("Before sender")
    sender = threading.Thread(name='tutorial', target=send_message, args=(message,))
    sender.start()
    print("after sender")

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)