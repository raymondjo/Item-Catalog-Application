from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
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
APPLICATION_NAME = "Item Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def login():
	state = ''.join(
		random.choice(string.ascii_uppercase + string.digits) for x in range(32))
	login_session['state'] = state
	# return "The current session state is %s" % login_session['state']
	return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
	# Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code, now compatible with Python3
	request.get_data()
	code = request.data.decode('utf-8')

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
	# Submit request, parse response - Python3 compatible
	h = httplib2.Http()
	response = h.request(url, 'GET')[1]
	str_response = response.decode('utf-8')
	result = json.loads(str_response)

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
		response.headers['Content-Type'] = 'application/json'
		return response

	stored_access_token = login_session.get('access_token')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_access_token is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user is already connected.'),
								 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Store the access token in the session for later use.
	login_session['access_token'] = access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']

	# see if user exists, if it doesn't make a new one
	user_id = getUserID(login_session['email'])
	if not user_id:
		user_id = createUser(login_session)
	login_session['user_id'] = user_id

	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']
	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
	flash("you are now logged in as %s" % login_session['username'])
	return output

# User Helper Functions


def createUser(login_session):
	newUser = User(name=login_session['username'], email=login_session[
				   'email'], picture=login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id


def getUserInfo(user_id):
	user = session.query(User).filter_by(id=user_id).one()
	return user


def getUserID(email):
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None

# DISCONNECT - Revoke a current user's token and reset their login_session



@app.route('/logout')
def logout():
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
		# Reset the user's sesson.
		del login_session['access_token']
		del login_session['gplus_id']
		del login_session['username']
		del login_session['email']
		del login_session['picture']

		return redirect(url_for('showCategories'))
	else:
	   return redirect(url_for('showCategories'))

def serialize(catalog, items):
	    """Return object data in easily serializeable format"""
	    return {
	    	'id': catalog.id,
	        'name': catalog.name,
			'Items': items
	    }

# show catalogs in json format
@app.route('/catalogs/JSON')
def showCategoriesJSON():
	catalogs = session.query(Category).all()
	catalogJson = []
	for catalog in catalogs:
		items = session.query(CategoryItem).filter_by(category_id = catalog.id).all()
		itemsJson = [item.serialize for item in items]
		catalogJson.append(serialize(catalog, itemsJson))

	return jsonify(CatalogsJson = catalogJson)


# Show all catalogs
@app.route('/')
@app.route('/catalog/')
def showCategories():

	categories = session.query(Category).all()
	# for category in categories:
	#     print "Category: " + category.name

	Items = session.query(CategoryItem).all()
	# for category in Items:
	#     print "Category: " + category.name

	return render_template('categories.html', categories = categories, Items = Items[:5])

@app.route('/catalog/<int:catalog_id>')
@app.route('/catalog/<int:catalog_id>/items')
def showCategory(catalog_id):
	categories = session.query(Category).all()
	category = session.query(Category).filter_by(id = catalog_id).first()
	categoryName = category.name
	categoryItems = session.query(CategoryItem).filter_by(category_id = catalog_id).all()
	categoryItemsCount = len(categoryItems)

	return render_template('category.html', categories = categories, categoryItems = categoryItems,
						   categoryName = categoryName, categoryItemsCount = categoryItemsCount)

@app.route('/catalog/<int:catalog_id>/items/<int:item_id>')
def showCategoryItem(catalog_id, item_id):
	categories = session.query(Category).all()

	category = session.query(CategoryItem).filter_by(id = item_id).first()
	creatorinfo = getUserInfo(category.user_id)
	return render_template('showCategoryItem.html', categories = categories, category = category, creatorinfo = creatorinfo)

@app.route('/catalog/add', methods=['GET', 'POST'])
def addCategoryItem():

	if 'username' not in login_session:
		return redirect('/login')

	if request.method == 'POST':
		if not request.form['name']:
			flash('Please add instrument name')
			return redirect(url_for('addCategoryItem'))

		if not request.form['description']:
			flash('Please add a description')
			return redirect(url_for('addCategoryItem'))

		newItem = CategoryItem(name = request.form['name'], description = request.form['description'], category_id = request.form['category'], user_id = login_session['user_id'])
		session.add(newItem)
		session.commit()

		return redirect(url_for('showCategories'))
	else:
		categories = session.query(Category).all()

		return render_template('addItem.html', categories = categories)

@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/edit', methods=['GET', 'POST'])
def editCategoryItem(catalog_id, item_id):
	if 'username' not in login_session:
		return redirect('/login')

	Item = session.query(CategoryItem).filter_by(id = item_id).first()

	creatorinfo = getUserInfo(Item.user_id)

	if creatorinfo.id != login_session['user_id']:
		return redirect('/login')

	categories = session.query(Category).all()

	if request.method == 'POST':
		if request.form['name']:
			Item.name = request.form['name']
		if request.form['description']:
			Item.description = request.form['description']
		if request.form['category']:
			Item.category_id = request.form['category']
		return redirect(url_for('showCategoryItem', catalog_id = Item.category_id ,item_id = Item.id))
	else:
		return render_template('editItem.html', categories = categories, categoryItem = Item)

@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteCategoryItem(catalog_id, item_id):
	if 'username' not in login_session:
		return redirect('/login')

	item = session.query(CategoryItem).filter_by(id = item_id).first()

	creatorinfo = getUserInfo(item.user_id)

	if creatorinfo.id != login_session['user_id']:
		return redirect('/login')

	categories = session.query(Category).all()

	if request.method == 'POST':
		session.delete(item)
		session.commit()
		return redirect(url_for('showCategory', catalog_id = item.category_id))
	else:
		return render_template('deleteItem.html', categories = categories, Item = item)



if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
