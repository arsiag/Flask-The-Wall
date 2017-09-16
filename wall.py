from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
from datetime import datetime, date, time
import re # to validate email and other criteria
import md5 # imports the md5 module to generate a hash to encrypt password
import os, binascii # include this to generate random salt

emailRegex = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
pwordRegex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$')

app = Flask(__name__)
app.secret_key = 'TheWall'

mysql = MySQLConnector(app,'wall')

@app.route('/')
def index():
    return render_template("LoginRegistration.html")

@app.route('/register', methods=['POST'])
def register():
    registerFlag = True

    # verify first name criteria
    if len(request.form['fname']) == 0:
        flash('First Name cannot be blank', 'registererror')
        registerFlag = False
    elif any(char.isdigit() for char in request.form['fname']):
        flash('First Name cannot have numbers', 'registererror')
        registerFlag = False

    # verify last name criteria
    if len(request.form['lname']) == 0:
        flash('Last Name cannot be blank', 'registererror')
        registerFlag = False
    elif any(char.isdigit() for char in request.form['lname']):
        flash('Last Name cannot have numbers', 'registererror')
        registerFlag = False

    # verify email criteria
    if len(request.form['email']) == 0:
        flash('Email cannot be blank', 'registererror')
        registerFlag = False
    elif not emailRegex.match(request.form['email']):
        flash('Invalid email address', 'registererror')
        registerFlag = False
    else:
        email = request.form['email']
        select_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
        query_data = { 'email': email }
        user = mysql.query_db(select_query, query_data)
        if user:
            flash("User already exists, please login!", 'registererror')
            return redirect ('/')

    # verify password criteria
    if len(request.form['pword']) == 0:
        flash('Password cannot be blank', 'registererror')
        registerFlag = False
    elif len(request.form['pword']) < 9:
        flash('Password must be greater than 8 characters long', 'registererror')
        registerFlag = False
    elif not pwordRegex.match(request.form['pword']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit', 'registererror')
        registerFlag = False

    # verify confirm password criteria
    if len(request.form['cpword']) == 0:
        flash('Confirm password cannot be blank', 'registererror')
        registerFlag = False
    elif request.form['cpword'] != request.form['pword']:
        flash('Passwords do not match', 'registererror')
        registerFlag = False

    # if everything is ok
    if registerFlag == True:
        password = request.form['pword']
        salt = binascii.b2a_hex(os.urandom(5))
        hashed_password = md5.new(password + salt).hexdigest()
        #pw_hash = bcrypt.generate_password_hash(password)
        
        insert_query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :hashed_password, :salt, NOW(), NOW())"
        data = {
            'first_name': request.form['fname'],
            'last_name': request.form['lname'],
            'email': request.form['email'],
            'hashed_password': hashed_password,
            'salt': salt,
        }
        insert_result = mysql.query_db(insert_query, data)
        if insert_result > 0:
            flash('Registration was successful! You can log in now.', 'registersuccess')
  
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['pword']
    select_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(select_query, query_data)
    if not user:
       flash("Please enter valid email.", 'loginerror')
       return redirect ('/')
    elif len(user) != 0:
        encrypted_password = md5.new(password + user[0]['salt']).hexdigest()

        if user[0]['password'] == encrypted_password:
            session['user_id'] = user[0]['id']
            session['first_name'] = user[0]['first_name']
            session['last_name'] = user[0]['last_name']
            flash('login was successful! You are logged in now!', 'loginsuccess')
            return redirect('/wall')
        else:
            flash('Invalid password!', 'loginerror')
            return redirect ('/')
    else:
        print "something went wrong!"
        flash('Something went wrong!', 'loginerror')
        return redirect ('/')

@app.route('/wall')
def wall():
    # initialize session messages
    if not session.get('messages'):
        session['messages'] = []

    # initialize session comments
    if not session.get('comments'):
        session['comments'] = []

    # get the all the messages from DB and store them in session
    message_query = "SELECT users.first_name, users.last_name, messages.id, messages.user_id, messages.message, date_format(messages.created_at, '%M %D %Y') AS msgdate FROM users JOIN messages ON users.id = messages.user_id ORDER BY messages.created_at DESC"
    session['messages'] = mysql.query_db(message_query)

    # get the all the comments from DB and store them in session
    comment_query = "SELECT users.first_name, users.last_name, comments.message_id, comments.user_id, comments.comment, date_format(comments.created_at, '%M %D %Y') AS cmntdate FROM comments JOIN users ON users.id = comments.user_id ORDER BY comments.created_at"
    session['comments'] = mysql.query_db(comment_query)

    if session['user_id']:
        return render_template('wall.html')
    else:
        return redirect('/')

@app.route('/wall/postmsg', methods=['POST'])
def post_message():

    # print "*********************************************"
    # print "Inserting into messages. user id is: " + str(session['user_id'])
    
    # get the new message from the form and store it in DB
    message_insert = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW())"
    data = {
        'user_id': session['user_id'],
        'message': request.form['message'],
    }
    message_result = mysql.query_db(message_insert, data)
  
    return redirect('/wall')

@app.route('/wall/postcmnt/<msgid>', methods=['POST'])
def post_comment(msgid):
    
    # print "*********************************************"
    # print "Inserting into comments. message id is: " + str(msgid)

    # get the new comment from the form and store it in DB
    comment_insert = "INSERT INTO comments (user_id, message_id, comment, created_at, updated_at) VALUES (:user_id, :message_id, :comment, NOW(), NOW())"
    data = {
        'message_id': msgid,
        'user_id': session['user_id'],
        'comment': request.form['comment'],
    }
    comment_result = mysql.query_db(comment_insert, data)

    return redirect('/wall')

@app.route('/wall/postmsg/delete/<msgid>', methods=['POST'])
def delete_message(msgid):

    # print "*********************************************"
    # print "Deleting from messages. message id is: " + str(msgid)

    message_delete = "DELETE FROM messages WHERE id = :msgid"
    data = {
        'msgid': msgid
    }
    delete_result = mysql.query_db(message_delete, data)

    return redirect('/wall')

@app.route('/logout', methods=['POST'])
def reset():
    session.clear()
    return redirect('/')

app.run(debug=True)