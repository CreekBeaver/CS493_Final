# -- The following Sets up the Auth0 Credentials. It is a combination of the material found
# in the Module 7 Exploration as well as the Start Up Link provided on the Auth0 Website
# Reference the following Links:
# Module 7 Exploration: https://canvas.oregonstate.edu/courses/1890665/pages/exploration-authentication-in-python?module_item_id=22486484
# Auth0 Getting Started: https://auth0.com/docs/quickstart/webapp/python

# -- This is all Log In Information For Kyle
# -- Google Cloud:
    # URL: https://console.cloud.google.com/projectselector2
    # Data Store: https://console.cloud.google.com/datastore/entities;kind=players;ns=__$DEFAULT$__/query/kind?project=creekk-final
# -- Auth0 Application: 
    # User: creekk@oregonstate.edu
    # Pass: Graduation2022
    # URL: https://manage.auth0.com/dashboard/us/creekk-cs493/applications/Ho4DGciVkO6dg5CA1wwHjJcNM6xvs3so/settings
    
# -- Import Sections
from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, Response
import requests
from functools import wraps
import json
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
import json
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

# -- Define the App and the Datastore Client
app = Flask(__name__)
client = datastore.Client()

app.secret_key = '8b623301154051a982b98d8f20942b465be4738f662d520138073f77cc84f083'

# - Reference URL: https://manage.auth0.com/dashboard/us/creekk-cs493/applications/Ho4DGciVkO6dg5CA1wwHjJcNM6xvs3so/settings
CLIENT_ID = 'Ho4DGciVkO6dg5CA1wwHjJcNM6xvs3so'
CLIENT_SECRET = 'ZxGKv4dEHNZwUEQl9pzd7bhn03ZdHDBPQL4wAZ8ayYx8nrcJQvcBIASAzgY_KfzP'
DOMAIN = 'creekk-cs493.us.auth0.com'

ALGORITHMS = ["RS256"]
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url='https://creekk-cs493.us.auth0.com/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga = 2.46956069.349333901.1589042886 - 466012638.1589042885
# create-the- jwt - validation - decorator
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response
# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)
        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)
# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

# -- Below Routes handle Home and Login
@app.route("/")
def home():

    # -- Need this If Statement to Pre Login Failures that occurred.
    if session.get('user') is not None:
        # Grab the redirect information and assign the username
        username = session.get('user')['userinfo']['email']
        # -- After the Log In I need to add the User to the DataBase
        query = client.query(kind='owners')
        results = list(query.fetch())

        new_user = True
        # -- Validate that this isn't a new username in the database
        for row in results:
            if username == row['username']:
                new_user = False

        # -- If this statement is True, then we need to upload it to the Database
        if new_user:
            new_owner = datastore.entity.Entity(key=client.key("owners"))
            new_owner.update({"username": username})
            client.put(new_owner)
        token = session.get('user')['id_token']
    if session.get('user') is None:
        username = 'Unknown'
        token = ''

    return render_template("home.html", session=session.get("user"),username=username,token=token)
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))

# -- The Below Shows all the "Owners" End Points"
@app.route('/owners', methods=['GET'])
def view_owners():
    if request.headers['Accept'] != "application/json":
        return Response(status=405)

    if request.method == 'GET':
        query = client.query(kind='owners')
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        # -- Need to Edit from here below to show the information that is going to be shown. 
        
        for row in results:
            print(row)
        
        #for e in results:
            #e["id"] = e.key.id
        output = {"owners": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    else:
        return 'Method not recogonized'

# -- The below relates to the "Players" End Points
@app.route('/players', methods=['POST', 'GET'])
def create_view_player():
    # -- Automatic Header Error
    if request.headers['Accept'] != "application/json":
        resp_text = {"Error": "Request Header must include 'Accept: application/json'"}
        return Response(json.dumps(resp_text), status=406)
    # -- Creates a new Player
    if request.method == 'POST':
        content = request.get_json()
        if "name" not in content.keys() or "height" not in content.keys() or "weight" not in content.keys():
            resp_text = {"Error": "Missing Attributes"}
            return Response(json.dumps(resp_text), status=400)


        new_player = datastore.entity.Entity(key=client.key("players"))
        new_player.update({"name": content["name"], "height": content["height"], "weight": content["weight"],
                           "current_team": None, "self": ""})
        client.put(new_player)
        # -- Have to Point To self AFTER this is made because it wont get an ID until after it's instantiated.
        self = str(request.base_url) + '/' + str(new_player.id)
        new_player.update({"self":self})
        client.put(new_player)
        resp_text = {"id": new_player.id, "name": new_player["name"], "height": new_player["height"], "weight": new_player["weight"],
                       "current_team": None, "self": new_player['self']}
        return Response(json.dumps(resp_text), status=201)

    # -- Returns a paginated list of players
    # -- Reference:https://canvas.oregonstate.edu/courses/1890665/pages/exploration-intermediate-rest-api-features-with-python?module_item_id=22486463
    if request.method == 'GET':
        query = client.query(kind='players')
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        output = {"players": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    else:
        return 'Method not recogonized'
@app.route('/players/<player_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def modify_player(player_id):
    if request.headers['Accept'] != "application/json":
        resp_text = {"Error": "Request Header must include 'Accept: application/json'"}
        return Response(json.dumps(resp_text), status=406)
    # -- View for a Specific Player
    if request.method == 'GET':
        player_key = client.key("players", int(player_id))
        player = client.get(key=player_key)
        # Valid Player ID
        if player is not None:
            resp_text = {"id": player.id, "name": player['name'], "height":player['height'],
                         "weight": player["weight"], "current_team": player['current_team'],
                         "self": player['self']}
            return Response(json.dumps(resp_text), status=200)

        # Invalid Player ID
        else:
            resp_text = {"Error": "Player not Found"}
            return Response(json.dumps(resp_text), status=404)
        
    # -- COMPLETE Edit for a Specific Player
    if request.method == 'PUT':
        content = request.get_json()
        # Repository to store all the Attribute Key Names
        key_names = ['name', 'height', 'weight']

        if "name" not in content.keys() or "height" not in content.keys() or "weight" not in content.keys():
            resp_text = {"Error": "Missing Attribute in Request Body"}
            return Response(json.dumps(resp_text), status=400)

        # Verify that the Player Exists
        player_key = client.key("players", int(player_id))
        player = client.get(key=player_key)

        # Invalid Player ID
        if player is None:
            resp_text = {"Error": "Player not Found"}
            return Response(json.dumps(resp_text), status=404)

        # -- Update the Player
        player['name'] = content['name']
        player['weight'] = content['weight']
        player['height'] = content['height']
        client.put(player)

        # -- Build Response
        resp_text = {"id": player.key.id, "name": player['name'], "height": player['height'],
                     "weight": player["weight"], "current_team": player['current_team'],
                     "self": player['self']}

        return Response(json.dumps(resp_text), status=200)
    
    # -- Partial Edit for a Specific Player
    if request.method == 'PATCH':
        content = request.get_json()
        # Repository to store all the Attribute Key Names
        key_names = ['name', 'height', 'weight']

        # Verify that the Player Exists
        player_key = client.key("players", int(player_id))
        player = client.get(key=player_key)

        # Invalid Player ID
        if player is None:
            resp_text = {"Error": "Player not Found"}
            return Response(json.dumps(resp_text), status=404)
        
        # -- Update the Player
        if 'name' in content.keys():
            player['name'] = content['name']

        if 'weight' in content.keys():
            player['weight'] = content['weight']

        if 'height' in content.keys():
            player['height'] = content['height']

        # -- Commit Changes
        client.put(player)

        # -- Build Response
        resp_text = {"id": player.id, "name": player['name'], "height": player['height'],
                     "weight": player["weight"], "current_team": player['current_team'],
                     "self": player['self']}

        return Response(json.dumps(resp_text), status=200)
    # -- Delete a Specific Player
    if request.method == 'DELETE':
        player_key = client.key("players", int(player_id))
        player = client.get(key=player_key)
        
        # Invalid Player ID
        if player is None:
            resp_text = {"Error": "Player not Found"}
            return Response(json.dumps(resp_text), status=404)

        # -- Remove the Player from the Team if the Team for the Player is NOT 'None"
        # -- JWT is Required for this Delete. Player will be removed from the Roster
        # and thus will be affecting a protected resource. 
        if player['current_team'] is not None:
            # If we are this Far, a JWT MUST be provided
            # -- Note: Missing Token will be handled by the "verify_jwt"
            payload = verify_jwt(request)

            # -- Obtain the Owner_ID
            # -- Identify the Owner of the Team and Obtain ownerID
            query = client.query(kind='owners')
            results = list(query.fetch())
            # -- Query the Results to find the Correct Owner ID
            for row in results:
                if payload['name'] == row['username']:
                    owner_id = row.id
                    
            # -- Review all Teams and Locate the team The Player is on
            query = client.query(kind='teams')
            results = list(query.fetch())
            for team in results:
                # Team nickname is Identified 
                if team['nickname'] == player['current_team']:
                    # Verify that the Provided JWT matches the Team Owner
                    if int(team['owner_id']) != owner_id:
                        resp_text = {"Error": "Player is on Team. Valid JWT must be provided to Delete Player on Team"}
                        return Response(json.dumps(resp_text), status=401)
                    
                    # If we get this far, then the Proper Credentials are provided and we can remove the player
                    team['players'].remove(player.id)
                    client.put(team)
                    
        # -- Delete the Player from the DataStore
        client.delete(player_key)
        return Response(status=204)

# -- Below Routes handle "Team" End Points
@app.route('/teams', methods=['POST', 'GET'])
def create_view_teams():
    # -- Automatic Header Error
    if request.headers['Accept'] != "application/json":
        resp_text = {"Error": "Request Header must include 'Accept: application/json'"}
        return Response(json.dumps(resp_text), status=406)
    # -- Creates a New Team
    if request.method == 'POST':
        # -- Verifies that the JWT is Valid
        # -- Note: Missing Token will be handled by the "verify_jwt"
        payload = verify_jwt(request)
        content = request.get_json()
        
        # -- Validate all Input 
        if "nickname" not in content.keys() or "city" not in content.keys() or "state" not in content.keys():
            resp_text = {"Error": "Missing Attributes"}
            return Response(json.dumps(resp_text), status=400)


        # -- Validate Name Uniqueness Constraint
        query = client.query(kind='teams')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if row['nickname'].lower() == content['nickname'].lower():
                resp_text = {"Error": "Name is Not Unique"}
                return Response(json.dumps(resp_text), status=403)

        # -- Query to Obtain the Owner ID:
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id

        new_team = datastore.entity.Entity(key=client.key("teams"))
        new_team.update({"nickname": content["nickname"], "city": content["city"], "state": content["state"],
                           "players": [], "owner_id": owner_id, "self": "" })
        client.put(new_team)
        # -- I have to do this silly update because of the Team Id not being valid
        # until AFTER the Client does the "PUT" Operation. 
        self = str(request.base_url) + "/" + str(new_team.id)
        new_team['self'] = self
        client.put(new_team)

        # -- Now Build the Response
        resp_text = {"id": new_team.id, "nickname": new_team['nickname'], 'city': new_team['city'],
                     'state': new_team['state'], 'players': new_team['players'], 'owner_id': owner_id,
                     "self": new_team['self']}

        return Response(json.dumps(resp_text), status=201)

    # -- Returns a Paginated list of Teams for a Provided Token
    if request.method == 'GET':
        # Verify the JWT Provided
        payload = verify_jwt(request)
        # -- Obtain the OwnerID
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id

        # -- Gather All the Teams
        query = client.query(kind='teams')
        results = list(query.fetch())

        # -- Create a Response Text
        resp_list = []
        for row in results:
            if int(row['owner_id']) == owner_id:
                resp_team = {"id": row.id, "nickname": row['nickname'], "city": row['city'],
                             'state': row['state'], 'players': row['players'],'owner_id': row['owner_id'], 'self': row['self']}
                resp_list.append(resp_team)
        resp_text = {"teams": resp_list}
        return Response(json.dumps(resp_text), status=200)
@app.route('/teams/<team_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def modify_team(team_id):
    # -- Automatic Header Error
    if request.headers['Accept'] != "application/json":
        resp_text = {"Error": "Request Header must include 'Accept: application/json'"}
        return Response(json.dumps(resp_text), status=406)
    # -- View for a Specific Team
    if request.method == 'GET':
        # Verify the JWT Provided
        payload = verify_jwt(request)
        # -- Obtain the OwnerID
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id

        team_key = client.key("teams", int(team_id))
        team = client.get(key=team_key)
        # Invalid Team ID
        if team is None:
            resp_text = {"Error": "Team not found"}
            return Response(json.dumps(resp_text), status=404)

        if int(team['owner_id']) != owner_id:
            resp_text = {"Error": "You are not the Right Owner"}
            return Response(json.dumps(resp_text), status=401)

        # If we get past here, everything is good.
        resp_text = {"id": team.id, "nickname": team['nickname'], "city": team['city'],
                             'state': team['state'], 'players': team['players'],'owner_id': team['owner_id'], 'self': team['self']}
        return Response(json.dumps(resp_text), status=200)
    # -- Partial Edit for a Specific Team
    if request.method == 'PATCH':
        content= request.get_json()
        # Verify the JWT Provided
        payload = verify_jwt(request)
        # Obtain the Team In Question
        team_key = client.key("teams", int(team_id))
        team = client.get(key=team_key)
        # Invalid Team ID
        if team is None:
            resp_text = {"Error": "Team not found"}
            return Response(json.dumps(resp_text), status=404)
        
        # -- Validate the Owner Owns the Actual Team
        # -- Obtain the OwnerID
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id
        
        # -- Handles Invalid JWT
        if int(team['owner_id']) != owner_id:
            resp_text = {"Error": "You are not the Right Owner"}
            return Response(json.dumps(resp_text), status=401)

        # -- Below This Line Starts the Edit Process
        if int(team['owner_id']) == owner_id:
            if 'nickname' in content.keys():
                # -- Validate Name Uniqueness Constraint
                query = client.query(kind='teams')
                results = list(query.fetch())
                # -- Query the Results to find the Correct Owner ID
                for row in results:
                    if row['nickname'].lower() == content['nickname'].lower():
                        resp_text = {"Error": "Name is Not Unique"}
                        return Response(json.dumps(resp_text), status=403)
                team['nickname'] = content['nickname']
            if 'city' in content.keys():
                team['city'] = content['city']
            if 'state' in content.keys():
                team['state'] = content['state']
            client.put(team)


            # -- Build Response
            resp_text = {"id": team.key.id, "nickname": team['nickname'], "city": team['city'],
                         "state": team["state"], "players": team['players'], 'owner_id': owner_id,
                         "self": team['self']}

            return Response(json.dumps(resp_text), status=200)

        # -- This is where the Owner IDs do not Match
        resp_text = {"Error": "Invalid JWT To delete this team"}
        return Response(json.dumps(resp_text), status=403)
    # -- Total Edit for a Specific Team
    if request.method == 'PUT':
        content= request.get_json()
        # Verify the JWT Provided
        payload = verify_jwt(request)
        
        # Obtain the Team In Question
        team_key = client.key("teams", int(team_id))
        team = client.get(key=team_key)
        # Invalid Team ID
        if team is None:
            resp_text = {"Error": "Team Not Found"}
            return Response(json.dumps(resp_text), status=404)
        
        # -- Invalid Key Input
        if "nickname" not in content.keys() or "city" not in content.keys() or "state" not in content.keys():
            resp_text = {"Error": "Missing Attribute"}
            return Response(json.dumps(resp_text), status=400)
        
        # -- Validate Name Uniqueness Constraint
        query = client.query(kind='teams')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if row['nickname'].lower() == content['nickname'].lower():
                resp_text = {"Error": "Name is Not Unique"}
                return Response(json.dumps(resp_text), status=403)
            
        # -- Validate the Owner Owns the Actual Team
        # -- Obtain the OwnerID
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id
        
        # -- Invalid Owner
        if int(team['owner_id']) != owner_id:
            resp_text = {"Error": "You are not the Right Owner"}
            return Response(json.dumps(resp_text), status=401)
        
        # -- Below This Everything is validated. 
        # -- Update the Player
        team['nickname'] = content['nickname']
        team['city'] = content['city']
        team['state'] = content['state']
        client.put(team)

        # -- Build Response
        resp_text = {"id": team.key.id, "nickname": team['nickname'], "city": team['city'],
                     "state": team["state"], "players": team['players'], 'owner_id': owner_id,
                     "self": team['self']}

        return Response(json.dumps(resp_text), status=200)
    # -- Delete a Specific Team
    if request.method == 'DELETE':
        # Verify the JWT Provided
        payload = verify_jwt(request)
        # Obtain the Team In Question
        team_key = client.key("teams", int(team_id))
        team = client.get(key=team_key)
        # Invalid Team ID
        if team is None:
            resp_text = {"Error": "Team not Found"}
            return Response(json.dumps(resp_text), status=404)
        # -- Validate the Owner Owns the Actual Team
        # -- Obtain the OwnerID
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id
        
        # -- Invalid Owner
        if int(team['owner_id']) != owner_id:
            resp_text = {"Error": "You are not the Right Owner"}
            return Response(json.dumps(resp_text), status=401)        
        
        # Delete Team with No Players
        if len(team['players']) == 0:
            client.delete(team_key)
            return Response(status=204)

        # -- Delete Team with Players on it
        if len(team['players']) != 0:
            for person in team['players']:
                # Obtain the Player Object
                player_key = client.key("players", int(int(person)))
                player = client.get(key=player_key)
                player['current_team'] = None
                client.put(player)
            client.delete(team_key)
            return Response(status=204)

# -- Below are the routes to add and remove a player from a team
@app.route('/teams/<team_id>/players/<player_id>', methods=['PUT', 'DELETE'])
def add_remove_players(team_id, player_id):
    if request.headers['Accept'] != "application/json":
        return Response(status=405)
    # -- Adds a player to a Team
    if request.method == 'PUT':
        payload = verify_jwt(request)

        # Verify the Player Exists
        player_key = client.key("players", int(player_id))
        player = client.get(key=player_key)

        if player is None:
            resp_text = {"Error": "Player/Team Not Found"}
            return Response(json.dumps(resp_text), status=404)

        # Verify the Player Isn't Already on a Team
        if player['current_team'] is not None:
            resp_text = {"Error": "Player is already on a Team"}
            return Response(json.dumps(resp_text), status=406)

        # Verify the Team Exists
        team_key = client.key("teams", int(team_id))
        team = client.get(key=team_key)
        # Invalid Team ID
        if team is None:
            resp_text = {"Error": "Player/Team Not Found"}
            return Response(json.dumps(resp_text), status=404)

        # Verify the JWT Owns the Team
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id
        # -- Invalid Owner
        if int(team['owner_id']) != owner_id:
            resp_text = {"Error": "You are not the Right Owner"}
            return Response(json.dumps(resp_text), status=401)  
        
        # -- Below This Line Starts the Edit Process
        # Add Player to Team Roster
        team['players'].append(int(player_id))
        client.put(team)
        # Add Team to Player 'Current Team'
        player['current_team'] = team['nickname']
        client.put(player)
        return Response(status=200)

    # -- Removes a Player from a Team
    if request.method == 'DELETE':
        payload = verify_jwt(request)

        # Verify the Player Exists
        player_key = client.key("players", int(player_id))
        player = client.get(key=player_key)

        if player is None:
            resp_text = {"Error": "Player/Team Not Found"}
            return Response(json.dumps(resp_text), status=404)
        
        # Verify the Player Isn't Already on a Team <- THis May require edit. 
        if player['current_team'] is None:
            return Response(status=200)
        
        # Verify the Team Exists
        team_key = client.key("teams", int(team_id))
        team = client.get(key=team_key)
        # Invalid Team ID
        if team is None:
            resp_text = {"Error": "Player/Team Not Found"}
            return Response(json.dumps(resp_text), status=404)

        # Verify the JWT Owns the Team
        query = client.query(kind='owners')
        results = list(query.fetch())
        # -- Query the Results to find the Correct Owner ID
        for row in results:
            if payload['name'] == row['username']:
                owner_id = row.id
        # -- Invalid Owner
        if int(team['owner_id']) != owner_id:
            resp_text = {"Error": "You are not the Right Owner"}
            return Response(json.dumps(resp_text), status=401)  
        
        # -- Below This Line Starts the Edit Process
        # Add Player to Team Roster
        team['players'].remove(int(player_id))
        client.put(team)
        # Add Team to Player 'Current Team'
        player['current_team'] = None
        client.put(player)
        return Response(status=200)
        
        
# -- Below is the "Main" Statement
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=3000, debug=True)