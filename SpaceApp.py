#!/usr/bin/env python
from flask import \
     Flask, \
     render_template, \
     request, \
     redirect, \
     jsonify, \
     url_for, \
     flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Company, Acheivment
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Space Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///space.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createCompany(login_session):
    newCompany = Company(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newCompany)
    session.commit()
    company = session.query(Company).filter_by(email=login_session['email']).one()
    return company.id


def getCompanyInfo(company_id):
    company = session.query(Company).filter_by(id=company_id).one()
    return company


def getCompanyID(email):
    try:
        company = session.query(Company).filter_by(email=email).one()
        return company.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Information
@app.route('/company/<int:company_id>/acheivment/JSON')
def companyAcheivmentJSON(company_id):
    company = session.query(Company).filter_by(id=company_id).one()
    items = session.query(Acheivment).filter_by(company_id=company_id).all()
    return jsonify(Acheivment=[i.serialize for i in items])


@app.route('/company/<int:company_id>/acheivment/<int:acheivment_id>/JSON')
def acheivmentJSON(company_id, acheivment_id):
    Acheivment_Item = session.query(Acheivment).filter_by(id=acheivment_id).one()
    return jsonify(Acheivment_Item=Acheivment_Item.serialize)


@app.route('/company/JSON')
def companiesJSON():
    companies = session.query(Company).all()
    return jsonify(companies=[r.serialize for r in companies])


# Show All companies
@app.route('/')
@app.route('/company/')
def showCompanies():
    companies = session.query(Company).order_by(asc(Company.name))
    acheivments = session.query(Acheivment).order_by(desc(Acheivment.id))
    if 'username' not in login_session:
        return render_template('publiccompanies.html', companies=companies, acheivments=acheivments)
    else:
        return render_template('companies.html', companies=companies, acheivments=acheivments)


# Create a new Company
@app.route('/company/new/', methods=['GET', 'POST'])
def newCompany():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCompany = Company(
            name=request.form['name'], email=login_session['email'],
            picture=login_session['picture'])
        session.add(newCompany)
        flash('New Company %s Successfully Created' % newCompany.name)
        session.commit()
        return redirect(url_for('showCompanies'))
    else:
        return render_template('newCompany.html')


# Edit Company
@app.route('/company/<int:company_id>/edit/', methods=['GET', 'POST'])
def editCompany(company_id):
    editedCompany = session.query(Company).filter_by(id=company_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedCompany.email != login_session['email']:
        return "<script>function myFunction() {alert('You are not authorized to edit this Company. Please create your own company in order to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedCompany.name = request.form['name']
            flash('Company Successfully Edited %s' % editedCompany.name)
            return redirect(url_for('showCompanies'))
    else:
        return render_template('editCompany.html', company=editedCompany)


# Delete a brand
@app.route('/company/<int:company_id>/delete/', methods=['GET', 'POST'])
def deleteCompany(company_id):
    companyToDelete = session.query(Company).filter_by(id=company_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if companyToDelete.email != login_session['email']:
        return "<script>function myFunction() {alert('You are not authorized to delete this company. Please create your own company in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(companyToDelete)
        flash('%s Successfully Deleted' % companyToDelete.name)
        session.commit()
        return redirect(url_for('showCompanies'))
    else:
        return render_template('deleteCompany.html', company=companyToDelete)


# Show specific Acheivment
@app.route('/acheivment/<int:acheivment_id>/')
def sAcheivment(acheivment_id):
    items = session.query(Acheivment).filter_by(id=acheivment_id).one()
    creator = getCompanyInfo(items.company_id)
    if 'username' not in login_session or creator.email != login_session['email']:
        return render_template('publicspecificAcheivment.html', item=items, creator=creator)
    else:
        return render_template('specificAcheivment.html', item=items, creator=creator)


# Show a Company
@app.route('/company/<int:company_id>/')
@app.route('/company/<int:company_id>/acheivemnt/')
def showCompany(company_id):
    company = session.query(Company).filter_by(id=company_id).one()
    acheivments = session.query(Acheivment).filter_by(company_id=company_id).all()
    if 'username' not in login_session or company.email != login_session['email']:
        return render_template('publicAcheivments.html', acheivments=acheivments, company=company)
    else:
        return render_template('Acheivments.html', acheivments=acheivments, company=company)


# Create a new acheivment
@app.route('/company/<int:company_id>/acheivment/new/', methods=['GET', 'POST'])
def newAcheivment(company_id):
    if 'username' not in login_session:
        return redirect('/login')
    company = session.query(Company).filter_by(id=company_id).one()
    if login_session['email'] != company.email:
        return "<script>function myFunction() {alert('You are not authorized to add acheivment items to this company. Please create your own company in order to add acheivments.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        newItem = Acheivment(title=request.form['title'],
                             description=request.form['description'],
                             company_id=company.id)
        session.add(newItem)
        session.commit()
        flash('New Acheivment %s Item Successfully Created' % (newItem.title))
        return redirect(url_for('showCompany', company_id=company_id))
    return render_template('newAcheivment.html', company=company)


# Edit Acheivment
@app.route('/company/<int:company_id>/acheivment/<int:acheivment_id>/edit', methods=['GET', 'POST'])
def editAcheivment(company_id, acheivment_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Acheivment).filter_by(id=acheivment_id).one()
    company = session.query(Company).filter_by(id=company_id).one()
    if login_session['email'] != company.email:
        return "<script>function myFunction() {alert('You are not authorized to edit acheivment items to this company. Please create your own company in order to edit acheivment.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Acheivment Successfully Edited')
        return redirect(url_for('showCompany', company_id=company_id))
    else:
        return render_template('editAcheivment.html', company_id=company_id, acheivment_id=acheivment_id, item=editedItem, company=company)


# Delete Acheivment
@app.route('/company/<int:company_id>/acheivment/<int:acheivment_id>/delete', methods=['GET', 'POST'])
def deleteAcheivment(company_id, acheivment_id):
    if 'username' not in login_session:
        return redirect('/login')
    company = session.query(Company).filter_by(id=company_id).one()
    itemToDelete = session.query(Acheivment).filter_by(id=acheivment_id).one()
    if login_session['email'] != company.email:
        return "<script>function myFunction() {alert('You are not authorized to delete acheivment items to this Company. Please create your own Company in order to delete items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Acheivment Successfully Deleted')
        return redirect(url_for('showCompany', company_id=company_id))
    else:
        return render_template('deleteAcheivment.html', item=itemToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCompanies'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCompanies'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
