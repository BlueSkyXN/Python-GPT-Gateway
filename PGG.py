from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import requests

app = Flask(__name__)
CORS(app)

# 定义相关的全局变量
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "TotelySecurePassword")
ACCESS_TOKENS = []
PUID = ""

API_KEYS = {}
with open("api_keys.txt", "r") as file:
    for line in file:
        key = line.strip()
        if key != "":
            API_KEYS["Bearer " + key] = True


@app.before_request
def admin_check():
    if request.path.startswith('/admin'):
        password = request.headers.get('Authorization')
        if password != ADMIN_PASSWORD:
            return 'Unauthorized', 401


@app.before_request
def authorization():
    if len(API_KEYS) != 0:
        if not API_KEYS.get(request.headers.get("Authorization")):
            return 'Unauthorized', 401


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
    ACCESS_TOKENS = data
    return 'tokens updated', 200


@app.route('/v1/chat/completions', methods=['OPTIONS'])
def options_handler():
    return jsonify({"message": "pong"}), 200


@app.route('/v1/chat/completions', methods=['POST'])
def nightmare_handler():
    data = request.get_json()
    # Convert the chat request to a ChatGPT request
    # Here we assume you have defined a method `convert_api_request()`
    translated_request = convert_api_request(data)

    auth_header = request.headers.get('Authorization')
    token = ACCESS_TOKENS[0] if ACCESS_TOKENS else None
    if auth_header:
        custom_access_token = auth_header.replace("Bearer ", "")
        if custom_access_token.startswith("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik1UaEVOVUpHTkVNMVFURTRNMEZCTWpkQ05UZzVNRFUxUlRVd1FVSkRNRU13UmtGRVFrRXpSZyJ9"):
            token = custom_access_token

    # Assuming `send_request()` is a function that sends a request to a chatGPT API
    response = send_request(translated_request, token)

    if response.status_code != 200:
        return response.text, response.status_code

    return response.text, 200


if __name__ == '__main__':
    app.run(debug=True)
