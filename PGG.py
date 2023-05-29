from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import requests
from threading import Lock
import queue
import uuid
import random

class AccessToken:
    def __init__(self, tokens):
        self.tokens = queue.Queue()
        for token in tokens:
            self.tokens.put(token)

        # Save the tokens to a file
        if not os.path.exists('access_tokens.json'):
            with open('access_tokens.json', 'w') as f:
                json.dump(tokens, f)
        else:
            with open('access_tokens.json', 'w') as f:
                json.dump(tokens, f)

    def get_token(self):
        if self.tokens.empty():
            return ""

        token = self.tokens.get()
        self.tokens.put(token)
        return token

# Create a new Flask app
app = Flask(__name__)
CORS(app)

# Initialize your access tokens
ACCESS_TOKENS = AccessToken(["token1", "token2", "token3"])

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "TotallySecurePassword")

PUID = ""


API_KEYS = {}
with open("api_keys.txt", "r") as file:
    for line in file:
        key = line.strip()
        if key != "":
            API_KEYS["Bearer " + key] = True


def convert_api_request(api_request):
    chatgpt_request = {
        'action': 'next',
        'parent_message_id': str(uuid.uuid4()),
        'model': 'text-davinci-002-render-sha',
        'history_and_training_disabled': True,
        'messages': []
    }

    model = api_request.get('model', '')
    if model.startswith('gpt-4'):
        chatgpt_request['model'] = model

    messages = api_request.get('messages', [])
    for api_message in messages:
        role = api_message.get('role', '')
        if role == 'system':
            role = 'critic'
        content = api_message.get('content', '')
        chatgpt_request['messages'].append({
            'id': str(uuid.uuid4()),
            'author': {'role': role},
            'content': {'content_type': 'text', 'parts': [content]}
        })

    return chatgpt_request



def send_request(chatgpt_request, access_token):
    url = os.getenv('API_REVERSE_PROXY', 'https://ai.fakeopen.com/api/conversation')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Accept': '*/*'
    }

    if access_token:
        headers['Authorization'] = 'Bearer ' + access_token

    try:
        response = requests.post(url, headers=headers, json=chatgpt_request)
        response.raise_for_status()  # 检查响应状态码，如果不是 2xx，则会抛出异常
    except requests.exceptions.RequestException as e:
        return 'Error: ' + str(e), 500

    return response

@app.before_request
def admin_check():
    if request.path.startswith('/admin'):
        password = request.headers.get('Authorization')
        if password is None:
            return 'Unauthorized: Missing Authorization header', 401
        elif password != ADMIN_PASSWORD:
            return 'Unauthorized: Invalid password', 401

@app.before_request
def authorization():
    if len(API_KEYS) != 0:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return 'Unauthorized: Missing Authorization header', 401
        
        api_key = API_KEYS.get(auth_header)
        if not api_key:
            return 'Unauthorized: Invalid API key', 401



@app.route('/admin/password', methods=['PATCH'])
def password_handler():
    data = request.get_json()
    if 'password' not in data:
        return 'password not provided', 400
    global ADMIN_PASSWORD
    ADMIN_PASSWORD = data['password']
    os.environ["ADMIN_PASSWORD"] = ADMIN_PASSWORD
    return 'password updated', 200


@app.route('/admin/puid', methods=['PATCH'])
def puid_handler():
    data = request.get_json()
    if 'puid' not in data:
        return 'puid not provided', 400
    global PUID
    PUID = data['puid']
    os.environ["PUID"] = PUID
    return 'puid updated', 200


@app.route('/admin/tokens', methods=['PATCH'])
def tokens_handler():
    data = request.get_json()
    if data is None or len(data) == 0:
        return 'tokens not provided', 400
    global ACCESS_TOKENS
    ACCESS_TOKENS = AccessToken(data)
    return 'tokens updated', 200

@app.route('/ping', methods=['GET'])
def ping_handler():
    return 'pong', 200

@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE'])
def home_handler():
    return 'Welcome to PGG<br/>Your current operation is ' + request.method, 200


@app.route('/v1/chat/completions', methods=['OPTIONS'])
def options_handler():
    return jsonify({"message": "pong"}), 200


@app.route('/v1/chat/completions', methods=['POST'])
def nightmare_handler():
    data = request.get_json()
    translated_request = convert_api_request(data)

    auth_header = request.headers.get('Authorization')
    token = ACCESS_TOKENS.get_token() if ACCESS_TOKENS else None
    if auth_header:
        custom_access_token = auth_header.replace("Bearer ", "")
        if custom_access_token.startswith("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik1UaEVOVUpHTkVNMVFURTRNMEZCTWpkQ05UZzVNRFUxUlRVd1FVSkRNRU13UmtGRVFrRXpSZyJ9"):
            token = custom_access_token

    response = send_request(translated_request, token)

    if response.status_code != 200:
        return response.text, response.status_code

    return response.text, 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
