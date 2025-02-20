from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_pymongo import PyMongo
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from datetime import datetime
from dotenv import load_dotenv
from bson.objectid import ObjectId
from functools import wraps
import asyncio
import os

from permit import Permit

import hypercorn.asyncio
from hypercorn.config import Config

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["MONGO_URI"] = f"mongodb://{os.getenv('MONGO_USERNAME')}:{os.getenv('MONGO_PASSWORD')}@localhost:27017/project_management"
mongo = PyMongo(app)

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# Permit.io setup
permit = Permit(
    pdp="http://localhost:7766",
    token="",
)

# Decorator to enforce authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Login route
@app.route('/login')
def login():
    if "user" in session:
        abort(404)
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for('callback', _external=True)
    )

# Callback route
@app.route('/login/callback')
def callback():
    token = oauth.auth0.authorize_access_token()
    session['user'] = token

    user_email = token["userinfo"]["email"]

    async def sync_and_assign():
        await permit.api.users.sync({
            "key": user_email,
            "email": user_email
        })

        await permit.api.users.assign_role(
            {
                "user": user_email,
                "role": "owner",  
                "tenant": "default"
            }
        )

    asyncio.run(sync_and_assign())
    return redirect(url_for('home'))

# Logout
@app.route('/logout')
def logout():
    """
    Logs the user out of the session and from the Auth0 tenant
    """
    session.clear()
    return redirect(
        "https://" + os.getenv("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": os.getenv("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


# Home route
@app.route('/')
@login_required
def home():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get projects from the MongoDB collection
    projects = mongo.db.projects.find()
    return render_template('home.html', projects=projects, user=session['user'])

# Add Project route
@app.route('/add_project', methods=['GET', 'POST'])
@login_required
async def add_project():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        
        user_email = session['user']['userinfo']['email']
        name = request.form['name']
        description = request.form['description']
        department = request.form['department']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        new_project = {
            'name': name,
            'description': description,
            'start_date': datetime.strptime(start_date, '%Y-%m-%d'),
            'end_date': datetime.strptime(end_date, '%Y-%m-%d'),
            'creator': user_email,
            'department': department
        }
        
        # Insert project into the database
        mongo.db.projects.insert_one(new_project)
        return redirect(url_for('home'))

    return render_template('add_project.html')

# Update Project route
@app.route('/update_project/<project_id>', methods=['GET', 'POST'])
@login_required
async def update_project(project_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Fetch the project using ObjectId
    project = mongo.db.projects.find_one({'_id': ObjectId(project_id)})
    
    if not project:
        return abort(404)

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        department = request.form['department']
        
        # Update project details in the database
        mongo.db.projects.update_one({'_id': ObjectId(project_id)}, {
            '$set': {
                'name': name,
                'description': description,
                'start_date': datetime.strptime(start_date, '%Y-%m-%d'),
                'end_date': datetime.strptime(end_date, '%Y-%m-%d'),
                'department' : department
            }
        })
        return redirect(url_for('home'))

    return render_template('update_project.html', project=project)



# Delete Project route
@app.route('/delete_project/<project_id>', methods=['POST'])
@login_required
async def delete_project(project_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        mongo.db.projects.delete_one({'_id': ObjectId(project_id)})
    except Exception as e:
        return abort(404)

    return redirect(url_for('home'))

@app.route('/project_details/<project_id>')
@login_required
def project_details(project_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    project = mongo.db.projects.find_one({'_id': ObjectId(project_id)})

    if project:
        project['start_date'] = project['start_date'].strftime('%Y-%m-%d')
        project['end_date'] = project['end_date'].strftime('%Y-%m-%d')
        
    return render_template('project_details.html', project=project)


if __name__ == '__main__':
    config = Config()
    config.bind = ["0.0.0.0:5000"]
    asyncio.run(hypercorn.asyncio.serve(app, config))

