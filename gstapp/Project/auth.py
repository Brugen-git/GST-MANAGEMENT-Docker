#This file is used to authenticate and identify the sign ins

from flask import request, redirect, url_for, make_response, render_template, flash
from werkzeug.security import check_password_hash, generate_password_hash
from Project import app, db, encryption
from Project.models import User

#default page home for logging in
@app.route('/')
def home():
    return render_template("Home.html")

# sends a post request to server with the login details
@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name')

    # we check if this user email is correct and exists in our database
    user = User.query.filter_by(email=email).first()

    # we check if this user name is correct and exists in our database
    username = User.query.filter_by(name=name).first()

    # If the username is not present, we raise an alert
    if not username:
        flash('Incorrect UserName')
        return redirect(url_for('home'))

    # If the user email or password is incorrect, we raise an alert
    if not user or not check_password_hash(user.password, password):
        flash('Wrong Password or Email')
        return redirect(url_for('home'))
    
    # If the user is registered as a tax payer we redirect them to tax payer page
    if user.role == "Tax_Payer":
        res = make_response(redirect(url_for('tax_payer_home', id=user.id)))
        res.set_cookie('SiteCookie', encryption(user.id), max_age=60 * 60 * 24)
        return res
    # If the user is registered as a accountant we redirect them to accountant page
    elif user.role == "Accountant":
        res = make_response(redirect(url_for('accountant_home', id=user.id)))
        res.set_cookie('SiteCookie', encryption(user.id), max_age=60 * 60 * 24)
        return res

# To sign up new taxpayers in the database we send post request to register, get request to get information
@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    #check if this user is already present in database
    user = User.query.filter_by(email=email).first()

    # If the user already exists in our database, we raise an alert
    if user:
        flash('Account already exists')
        # We redirect the user to home page so they can login again
        return redirect(url_for('home'))

    # We create a new_user object 
    new_user = User(name=name, email=email, password=generate_password_hash(password, method='sha256'))

    #adding the new user into database
    db.session.add(new_user)
    db.session.commit()
    # redirect user tp tax_payer home page
    res = make_response(redirect(url_for('tax_payer_home', id=new_user.id)))
    res.set_cookie('SiteCookie', encryption(new_user.id), max_age=60 * 60 * 24)
    
    return res
