from os import environ
from pymongo.common import validate
from datetime import time
from flask import Flask, request, redirect, session, Response
from flask_hashing import Hashing
from flask_cors import CORS
import uuid
import pymongo
import random
import string
import time
from pymongo.message import update
import user_agents
import requests
import json
from dotenv import load_dotenv
try:
    # Running from the api directory
    from keyMakeSignCheck.KeyManagement import Signee
except:
    # Running from the root directory
    from api.keyMakeSignCheck.KeyManagement import Signee

load_dotenv()
MONGODB_CONNECTION_STRING = environ.get('MONGODB_CONNECTION_STRING')
RECAPTCHA_SECRET = environ.get('RECAPTCHA_SECRET')
SIGNEE_PUBLICKEY = environ.get('SIGNEE_PUBLICKEY')
SIGNEE_PRIVATEKEY = environ.get('SIGNEE_PRIVATEKEY')

# signee = Signee.fromFile(open('keys.json', 'r'))
signee = Signee(SIGNEE_PUBLICKEY, SIGNEE_PRIVATEKEY)

client = pymongo.MongoClient(MONGODB_CONNECTION_STRING)
db = client['codetools']
users = db['users']
codes = db['codes']
content = db['content']

app = Flask(__name__)
hashing = Hashing(app)
cors = CORS(app, supports_credentials=True)
app.secret_key = "blah blah blah"

app.config.update(SESSION_COOKIE_SAMESITE='None', SESSION_COOKIE_SECURE=True)

DEFAULT_CODE = """public int myMethod(int a) {
	return a + 1;
}"""
DEFAULT_SOLUTION = """public int solution(int a) {
	return a + 1;
}"""
DEFAULT_STARTER_CODE = """public int myMethod(int a) {

}"""


def make_linkID():
    return ''.join(random.choice(string.ascii_letters+string.digits) for x in range(12))


def make_ID(num):
    return ''.join(random.choice(string.ascii_letters+string.digits) for x in range(num))


def make_salt():
    return ''.join(random.choice(string.ascii_letters+string.digits) for x in range(16))


def make_sess_key():
    return ''.join(random.choice(string.ascii_letters+string.digits) for x in range(64))


def validate(session):
    if 'username' in session:
        data = users.find_one({'username': session['username']})
        if data != None:
            if 'sessionID' in session:
                try:
                    sessionIDs = [i['id'] for i in data['sessions']]
                    index = sessionIDs.index(session['sessionID'])
                    if hashing.check_value(data['sessions'][index]['hash'], session['sessionKey'], data['sessions'][index]['salt']):
                        return True
                    else:
                        return False
                except:
                    return False
            else:
                return False
        else:
            return False
    else:
        return False


try:
    errorsFile = open("./errors.json", "r")
except:
    try:
        errorsFile = open("./api/errors.json", "r")
    except:
        print("Could not open errors.json file.")
        exit()

try:
    ERRORS = json.loads(errorsFile.read())
except:
    print("Could not parse errors.json file.")
    exit()

def error_json(error):
    if error in ERRORS:
        return Response(json.dumps({'status': 'error', 'errorCode': error, 'error':ERRORS[error]}), mimetype="application/json")
    else:
        return Response(json.dumps({'status': 'error', 'errorCode':"api_unknown", 'error': error}), mimetype="application/json")


def warn_json(warning):
    return Response(json.dumps({'status': 'warn', 'warning': warning}), mimetype="application/json")


def success_json(data=None):
    if data:
        return Response(json.dumps({'status': 'success', 'data': data}), mimetype="application/json")
    else:
        return Response(json.dumps({'status': 'success'}), mimetype="application/json")

# def permissionCleanse(values):
# 	clean = True
# 	for value in values:
# 		if type(value) == dict:

# 		elif value[0] == '#':
# 			values.pop(value)


# @app.route('/selfcrash')
# def selfCrash():
# 	return str(0/0)

@app.route("/")
@app.route("/api")
def index():
    return success_json({'sampleData':'This is a sample response from the CodeTools API to show that it is working.'})

@app.route('/contentset', methods=['POST'])
@app.route('/api/contentset', methods=['POST'])
def contentSet():
    print(request.json)
    try:
        setRequest = request.json
    except:
        return error_json("api_contentset_jsonParse")
    towrite = {}
    if "contentID" not in setRequest:
        return error_json("api_general_contentId")
    contentBefore = content.find_one({'_id': setRequest['contentID']})
    if not contentBefore:
        return error_json("api_general_contentNotFound")
    if not validate(session):
        return error_json("api_general_session")
    userData = users.find_one({'username': session['username']})
    owner = contentBefore['owner'] == userData['_id']
    # extraWarn = None
    if 'code' in setRequest and owner:
        towrite['code'] = setRequest['code']
        towrite['modified'] = float(time.time())
    if 'args_mutable' in setRequest and owner:
        if type(setRequest['args_mutable']) == list:
            towrite['args_mutable'] = setRequest['args_mutable']
            towrite['modified'] = float(time.time())
    if 'description' in setRequest and owner:
        # if type(setRequest['description']) == string:
        towrite['description'] = setRequest['description']
        towrite['modified'] = float(time.time())
    if 'runMethod' in setRequest and owner:
        if type(setRequest['runMethod']) == str:
            towrite['runMethod'] = setRequest['runMethod']
            towrite['modified'] = float(time.time())
    if contentBefore['type'] == 'challenge':
        if 'instructions' in setRequest and owner:
            setRequest['instructions'] = setRequest['instructions'].replace(
                "<safe>", "")
            setRequest['instructions'] = setRequest['instructions'].replace(
                "</safe>", "")
            towrite['instructions'] = setRequest['instructions']
            towrite['modified'] = float(time.time())
        if 'starterCode' in setRequest and owner:
            towrite['starterCode'] = setRequest['starterCode']
            towrite['modified'] = float(time.time())
    if contentBefore['type'] in ['challenge', 'editor_standalone']:
        if 'title' in setRequest and owner:
            towrite['title'] = setRequest['title']
        if 'timeout' in setRequest and owner and type(setRequest['timeout']) == int:
            towrite['timeout'] = setRequest['timeout']

        towrite['modified'] = float(time.time())

    if not towrite:
        if owner:
            return warn_json("Did not write anything, maybe formatted wrong")
        else:
            return warn_json("Did not write anything, maybe formatted wrong, fyi: you do not own this content")
    else:
        content.update_one({'_id': setRequest['contentID']}, {'$set': towrite})
        return json.dumps({'status': 'success', 'modified': [key for key in towrite]})


@app.route('/contentget')
@app.route('/api/contentget')
def contentGet():
    try:
        contentID = request.args['id']
    except:
        return error_json("api_general_contentId")
    userContent = content.find_one({'_id': contentID})
    if not userContent:
        return error_json("api_general_contentNotFound")
    if not validate(session):
        return error_json("api_general_session")
    userData = users.find_one({'username': session['username']})
    owner = userContent['owner'] == userData['_id']
    signature = signee.sign(userContent['_id'])
    userContent['id_sig'] = signature
    if userContent['type'] == 'challenge' and not owner:
        ALLOWED_CHALLENGE_FIELDS = ['_id', 'title',
                                    'description', 'owner', 'modified']
        return success_json({key: userContent[key] for key in userContent if key in ALLOWED_CHALLENGE_FIELDS})
    if owner:
        return success_json(userContent)
    else:
        return error_json("api_general_contentReadPermission")


@app.route("/api/signin", methods=['POST'])
def api_signin():
    requestData = request.get_json(force=True)
    if request.method == 'POST':
        data = users.find_one({'username': requestData['username']})
        if data == None:
            return error_json("api_signin_userNotFound")
        if hashing.check_value(data['password_hash'], requestData['password'], salt=data['password_salt']):
            newSessionID = str(uuid.uuid4())
            newSessionKey = make_sess_key()
            newSessionSalt = make_salt()
            print(data['_id'])
            users.update_one({'_id': data['_id']}, {'$addToSet': {'sessions': {
                'id': newSessionID,
                'hash': hashing.hash_value(newSessionKey, salt=newSessionSalt),
                'salt': newSessionSalt,
                'time': str(time.time()),
                'userAgent': str(request.user_agent)
            }}})
            session['username'] = data['username']
            session['sessionID'] = newSessionID
            session['sessionKey'] = newSessionKey
            session['api'] = True
            return success_json()
        else:
            return error_json("api_general_wrongPassword")

@app.route('/api/signout')
def signout():
    try:
        users.update_one({'username': session['username']}, {
            '$pull': {'sessions': {'id': session['sessionID']}}})
        session.pop('sessionID')
        session.pop('sessionKey')
    except:
        return error_json("Failed to sign out.")
    return success_json()

@app.route("/api/signup", methods=['POST'])
def api_signup():
    requestData = request.get_json(force=True)
    if request.method == 'POST':
        # print(requestData)
        if 'g-recaptcha-response' not in requestData:
            return error_json("api_signup_reCaptchaNotRecieved")
        recaptcha_reponse = json.loads(requests.post('https://www.google.com/recaptcha/api/siteverify', {
            'secret': RECAPTCHA_SECRET, 'response': requestData['g-recaptcha-response']}).text)
        print(recaptcha_reponse)
        if recaptcha_reponse['success']:
            if len(requestData['username']) > 2 and len(requestData['password']) > 7:
                data = users.find_one({'username': requestData['username']})
                if data == None:
                    some_salt = make_salt()
                    actualname = requestData['username']
                    if requestData['actualname'] != "":
                        actualname = requestData['actualname']
                    users.insert_one({
                        '_id': str(uuid.uuid4()),
                        'username': requestData['username'],
                        'actualname': actualname,
                        'password_hash': hashing.hash_value(requestData['password'], salt=some_salt),
                        'password_salt': some_salt,
                        'sessions': []
                    })
                else:
                    return error_json("api_signup_userExists")
            else:
                return error_json("api_signup_length")
        else:
            return error_json("api_signup_reCaptchaVerification")
        return success_json()


@app.route('/api/sessions')
def listSessions():
    if validate(session):
        data = users.find_one({'username': session['username']})
        return success_json(data['sessions'])
    else:
        session['intent'] = "/sessions"
        return redirect("/signin")


@app.route('/fetchsession')
@app.route('/api/fetchsession')
def fetchAuth():
    if validate(session):
        sessID_sig = signee.sign(session['sessionID'])
        return success_json({**session, 'sessionID_sig': sessID_sig})
    else:
        return error_json("api_general_session")


@app.route('/api/killsession/<sessionID>')
def api_killSession(sessionID):
    if validate(session):
        try:
            users.update_one({'username': session['username']}, {
                '$pull': {'sessions': {'id': sessionID}}})
            return success_json()
        except:
            return error_json("Failed to kill session")
    else:
        return error_json("api_general_session")


@app.route("/api/changepassword", methods=['POST'])
def api_changePassword():
    requestData = request.get_json(force=True)
    if validate(session):
        if request.method == 'POST':
            data = users.find_one({'username': session['username']})
            if hashing.check_value(data['password_hash'], requestData['oldpass'], salt=data['password_salt']):
                if len(requestData['newpass']) > 7:
                    some_salt = make_salt()
                    users.update_one({'username': session['username']}, {'$set': {
                        'password_hash': hashing.hash_value(requestData['newpass'], salt=some_salt),
                        'password_salt': some_salt,
                    }})
                    return success_json()
                else:
                    return error_json("api_changepassword_length")
            else:
                return error_json("api_general_wrongPassword")
    else:
        error_json("api_general_session")


@app.route("/api/deleteaccount", methods=['POST'])
def api_deleteAccount():
    requestData = request.get_json(force=True)
    if validate(session):
        if request.method == 'POST':
            data = users.find_one({'username': session['username']})
            if hashing.check_value(data['password_hash'], requestData['password'], salt=data['password_salt']):
                users.delete_one({'username': session['username']})
                return success_json()
            else:
                return error_json("api_general_wrongPassword")
    else:
        return error_json("api_general_session")


@app.route("/api/changeactualname", methods=['POST'])
def api_changeActualName():
    requestData = request.get_json(force=True)
    if validate(session):
        if request.method == 'POST':
            if len(requestData['newName']) > 0:
                users.update_one({'username': session['username']}, {
                    '$set': {'actualname': requestData['newName']}})
            else:
                return error_json("api_changeactualname_length")
        return success_json()
    else:
        return error_json("api_general_session")


@app.route('/api/accountdata')
def api_account():
    if validate(session):
        accountData = users.find_one({'username': session['username']})
        for sess in accountData['sessions']:
            if sess['id'] == session['sessionID']:
                sess['current'] = True
            userAgent = user_agents.parse(sess['userAgent'])
            sess['readableUserAgent'] = userAgent.browser.family + \
                " on " + userAgent.os.family
            sess.pop('hash')
            sess.pop('salt')
        accountData['sessions'] = sorted(
            accountData['sessions'], key=lambda k: k['time'], reverse=True)
        if not 'actualname' in accountData:
            users.update_one({'username': accountData['username']}, {
                '$set': {'actualname': accountData['username']}})
            accountData = users.find_one({'username': session['username']})
        accountData.pop("password_hash")
        accountData.pop("password_salt")
        return success_json(accountData)
    else:
        return error_json("api_general_session")


@app.route("/api/myContent")
def api_mycontent():
    if validate(session):
        accountData = users.find_one({'username': session['username']})
        myContent = list(content.find({'owner':accountData['_id']}))
        # myContent = sorted(myContent, key=lambda k: k['modified'], reverse=True)
        attemptedChallenges = [element for element in myContent if element['type']=="editor_challenge"]
        assocChallenges = list(content.find({'_id':{'$in':[element['assocChallenge'] for element in attemptedChallenges]}}))
        output = []
        for element in myContent:
            newDict = {}
            for key in ['_id', 'type', 'modified']:
                newDict[key] = element[key]
            if element['type'] == "editor_challenge":
                try:
                    assocChallenge = [challenge for challenge in assocChallenges if challenge['_id']==element['assocChallenge']][0]
                    newDict['linkID'] = assocChallenge['linkID']
                except Exception as e:
                    print(e)
                    assocChallenge = {'title':'[ERROR] Original challenge missing'}
                newDict['title'] = assocChallenge['title']
            else:
                for key in ['title', 'linkID']:
                    newDict[key] = element[key]
            output.append(newDict)
        output = sorted(output, key=lambda k: k['modified'], reverse=True)
        print(output)
        if not output:
            return Response(json.dumps({'status': 'success', 'data': []}), mimetype="application/json")
        return success_json(output)
    else:
        return error_json("api_general_session")

@app.route("/api/new/<contentType>")
def api_newContent(contentType):
    if validate(session):
        userData = users.find_one({'username': session['username']})
        print(contentType)
        if contentType not in ['challenge', 'editor_standalone']:
            return error_json("api_new_contentType")
        linkID = make_linkID()
        newContent = {
                'type': contentType,
                '_id': str(uuid.uuid4()),
                'description': '## Edit me in the Description tab with Markdown',
                'title': 'Untitled',
                'name': linkID,
                'linkID': linkID,
                'owner': userData['_id'],
                'created': float(time.time()),
                'modified': float(time.time()),
                'args_mutable': [],
                'visibility': 'private',
            }
        if contentType == "challenge":
            newContent = {
                **newContent, 
                'code': DEFAULT_SOLUTION,
                'starterCode': DEFAULT_STARTER_CODE
            }
        if contentType == "editor_standalone":
            newContent = {
                **newContent, 
                'code': DEFAULT_CODE,
                'starterCode': DEFAULT_STARTER_CODE
            }
        content.insert_one(newContent)
        return success_json(newContent)
    else:
        return error_json("api_general_session")

@app.route("/api/delete/<contentID>")
def api_deleteContent(contentID):
    contentData = content.find_one({'_id': contentID})
    if contentData == None:
        return error_json("api_general_contentNotFound")
    if validate(session):
        userData = users.find_one({'username': session['username']})
        if contentData['owner'] == userData['_id']:
            content.delete_one({'_id':contentID})
            return success_json()
        else:
            return error_json("api_general_contentWritePermission")
    else:
        error_json("api_general_session")


@app.route("/api/getContentFromLinkID/<linkID>")
def api_getContent(linkID):
    contentData = content.find_one({'linkID': linkID})
    if contentData == None:
        return error_json("api_general_contentNotFound")
    if validate(session):
        userData = users.find_one({'username': session['username']})
        # pageName = "Challenge"
        # if contentData['type'] == 'challenge':
        #     pageName = contentData['name']+": editing challenge"
        # if contentData['type'] == 'editor_standalone':
        #     pageName = contentData['name']+": editing"
        if contentData['owner'] == userData['_id']:
            return success_json(contentData)
        elif contentData['type'] == 'challenge':
            editorChallenge = content.find_one(
                {'owner': userData['_id'], 'type': 'editor_challenge', 'assocChallenge': contentData['_id']})
            if not editorChallenge:
                contentID = str(uuid.uuid4())
                args_immutable = [{'id': arg['id'], 'arg':arg['arg'],
                                   'match':False} for arg in contentData['args_mutable']]
                newContent = {
                    '_id': contentID,
                    'type': 'editor_challenge',
                    'owner': userData['_id'],
                    'assocChallenge': contentData['_id'],
                    'description':contentData['description'],
                    'created': float(time.time()),
                    'modified': float(time.time()),
                    'args_mutable': [],
                    'args_immutable': args_immutable,
                    'code': contentData['starterCode']
                }
                content.insert_one(newContent)
            else:
                contentID = editorChallenge['_id']
            return success_json({'_id':contentID, 'type':'editor_challenge'})
        else:
            return error_json("api_general_contentReadPermission")
    else:
        return error_json("api_general_session")


@app.route("/api/republish/<contentID>", methods=['GET', 'POST'])
def api_republish(contentID):
    contentData = content.find_one({'_id': contentID})
    if contentData == None:
        return error_json("api_general_contentNotFound")
    if validate(session):
        if contentData['type'] == 'challenge':
            updateKeys = ['description', 'args', 'starterCode']
            if request.method == "POST":
                requestData = request.get_json(force=True)
                updateKeys = requestData
            if len(updateKeys)<1:
                error_json("api_republish_noneSelected")
            change = {}
            if 'description' in updateKeys:
                change['description'] = contentData['description']
            if 'args' in updateKeys:
                change['args_immutable'] = [
                    {'id':arg['id'], 'arg':arg['arg'], 'match':False} for arg in contentData['args_mutable']
                ]
            if 'starterCode' in updateKeys:
                change['code'] = {'$concat': [
                                '$code', '\n\n//STARTER CODE REPUBLISHED, SEE BELOW\n//'+contentData['starterCode'].replace('\n', '\n//')
                            ]}
            print(change)
            content.update_many({ 'assocChallenge': contentID },  [{ '$set': change }])
            return success_json()
        else:
            return error_json("api_republish_contentType")
    else:
        return error_json("api_general_session")


@app.route("/api/challengeresults/<contentID>")
def api_challengeResults(contentID):
    contentData = content.find_one({'_id': contentID})
    if contentData == None:
        return error_json("api_general_contentNotFound")
    if validate(session):
        if contentData['type'] == 'challenge':
            responses = list(content.find({'assocChallenge': contentID}))
            owners = list(users.find({'_id':{'$in':[element['owner'] for element in responses]}}))
            output = []
            for element in responses:
                newDict = element.copy()
                COPYKEYS = ['username', 'actualname']
                try:
                    owner = [owner for owner in owners if owner['_id']==element['owner']][0]
                    newDict['owner'] = {key:owner[key] for key in COPYKEYS}
                except Exception as e:
                    print(e)
                    newDict['owner'] = {"[ERROR] User not found" for key in COPYKEYS}
                output.append(newDict)
            return success_json(output)
        else:
            return error_json("api_challengeresults_contentType")
    else:
        return error_json("api_general_session")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=False)
