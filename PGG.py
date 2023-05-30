from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import os
import json
import requests
from threading import Lock
import queue
import uuid
import random
import logging

# 创建一个用于将日志输出到文件的处理器
handler = logging.FileHandler('app.log')

# 创建一个定义日志信息格式的格式化程序
formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')

# 为处理器设置格式化程序
handler.setFormatter(formatter)

# 创建Logger对象，并为每个Logger设置处理器
LOGGERS = {
    'send_request': logging.getLogger('send_request'),
    'received_data': logging.getLogger('received_data'),
    'final_response': logging.getLogger('final_response'),
}

# 遍历并设置Logger的处理器和级别
for logger_name, logger in LOGGERS.items():
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# 设置调试级别函数
def set_debug_level(level):
    level = level.lower()
    if level == "debug":
        for logger in LOGGERS.values():
            logger.setLevel(logging.DEBUG)
    elif level == "info":
        for logger in LOGGERS.values():
            logger.setLevel(logging.INFO)
    elif level == "warning":
        for logger in LOGGERS.values():
            logger.setLevel(logging.WARNING)
    elif level == "error":
        for logger in LOGGERS.values():
            logger.setLevel(logging.ERROR)
    elif level == "critical":
        for logger in LOGGERS.values():
            logger.setLevel(logging.CRITICAL)

DEBUG_LEVEL = "info"
set_debug_level(DEBUG_LEVEL)

# 访问令牌类
class AccessToken:
    def __init__(self, tokens):
        self.tokens = queue.Queue()
        for token in tokens:
            self.tokens.put(token)

        # 保存令牌到文件
        with open('access_tokens.json', 'w') as f:
            json.dump(tokens, f)

    # 获取令牌方法
    def get_token(self):
        if self.tokens.empty():
            return ""

        token = self.tokens.get()
        self.tokens.put(token)
        return token


# 创建一个新的Flask应用
app = Flask(__name__)
CORS(app)

# 初始化访问令牌
ACCESS_TOKENS = AccessToken(["token1", "token2", "token3"])

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "TotallySecurePassword")

API_KEYS = {}
with open("api_keys.txt", "r") as file:
    for line in file:
        key = line.strip()
        if key != "":
            API_KEYS["Bearer " + key] = True

# API请求转换函数
def convert_api_request(api_request):
    chatgpt_request = {
        'action': 'next',
        'parent_message_id': str(uuid.uuid4()),
        'model': 'text-davinci-002-render-sha',
        'history_and_training_disabled': True,
        'messages': [],
        'stream': False
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



# 发送请求函数
def send_request(chatgpt_request, access_token):
    url = os.getenv('API_REVERSE_PROXY', 'https://ai.fakeopen.com/api/conversation')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Accept': '*/*'
    }

    if access_token:
        headers['Authorization'] = 'Bearer ' + access_token

    LOGGERS['send_request'].info('正在发送请求: %s', json.dumps(chatgpt_request))  # 记录发送的请求内容
    LOGGERS['send_request'].info('已发送带有头部的请求: %s', headers) 

    try:
        response = requests.post(url, headers=headers, json=chatgpt_request, timeout=300, verify=False)
        response.raise_for_status()  # 检查响应状态码，如果不是 2xx，则会抛出异常
    except requests.exceptions.RequestException as e:
        LOGGERS['send_request'].error('发生错误: %s', str(e)) 
        return Response('Error: ' + str(e), 500)

    LOGGERS['received_data'].info('响应头部: %s', response.headers)  # 打印响应头部信息
    LOGGERS['received_data'].info('完整响应: %s', response.text)  # 记录完整响应

    return response



# 对请求进行管理员检查
@app.before_request
def admin_check():
    if request.path.startswith('/admin'):
        password = request.headers.get('Authorization')
        if password is None:
            return 'Unauthorized: Missing Authorization header', 401
        elif password != ADMIN_PASSWORD:
            return 'Unauthorized: Invalid password', 401

# 对请求进行授权检查
@app.before_request
def authorization():
    if len(API_KEYS) != 0:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return 'Unauthorized: Missing Authorization header', 401
        
        api_key = API_KEYS.get(auth_header)
        if not api_key:
            return 'Unauthorized: Invalid API key', 401

# 管理员密码处理器
@app.route('/admin/password', methods=['PATCH'])
def password_handler():
    data = request.get_json()
    if 'password' not in data:
        return '密码未提供', 400

    password = data['password']
    # 检查密码长度
    if len(password) < 8:
        return '密码太短，至少需要8个字符', 400
    # 检查密码复杂性，这只是一个简单的例子，你可以根据需要增加更复杂的检查
    if not any(char.isdigit() for char in password):
        return '密码必须至少包含一个数字', 400

    global ADMIN_PASSWORD
    ADMIN_PASSWORD = password
    os.environ["ADMIN_PASSWORD"] = ADMIN_PASSWORD
    return '密码已更新', 200

# 令牌处理器
@app.route('/admin/tokens', methods=['PATCH'])
def tokens_handler():
    data = request.get_json()
    if data is None or len(data) == 0:
        return 'tokens not provided', 400
    global ACCESS_TOKENS
    ACCESS_TOKENS = AccessToken(data)
    return 'tokens updated', 200


# ping处理器
@app.route('/ping', methods=['GET'])
def ping_handler():
    return 'pong', 200

# 首页处理器
@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE'])
def home_handler():
    return '欢迎访问PGG<br/>您当前的操作是 ' + request.method, 200

# option请求处理器
@app.route('/v1/chat/completions', methods=['OPTIONS'])
def options_handler():
    return jsonify({"message": "pong"}), 200


# post请求处理器
@app.route('/v1/chat/completions', methods=['POST'])
def nightmare_handler():
    data = request.get_json()
    LOGGERS['received_data'].info('接收到的数据: %s', data)  # 这里添加日志记录
    
    translated_request = convert_api_request(data)

    auth_header = request.headers.get('Authorization')
    token = ACCESS_TOKENS.get_token() if ACCESS_TOKENS else None
    if auth_header:
        custom_access_token = auth_header.replace("Bearer ", "")
        if custom_access_token.startswith("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik1UaEVOVUpHTkVNMVFURTRNMEZCTWpkQ05UZzVNRFUxUlRVd1FVSkRNRU13UmtGRVFrRXpSZyJ9"):
            token = custom_access_token

    response = send_request(translated_request, token)

    if response.status_code != 200:
        return response.get_data(as_text=True), response.status_code

    # 处理返回的数据
    final_message = None
    for line in response.content.decode().split("\n"):
        if line.startswith("data:"):
            message = json.loads(line[5:])  # 移除 "data:" 并解析 JSON
            if message["message"]["status"] == "finished_successfully" and message["message"]["author"]["role"] == "assistant":
                final_message = message
                break

    # 使用新的格式化函数
    formatted_response = format_response(final_message)
    # 返回处理后的数据
    LOGGERS['final_response'].info('最终响应: %s', formatted_response)
    return json.dumps(formatted_response), 200
    #原始返回代码
    # return json.dumps(final_message), 200


# 黑名单版本
def format_response_black(data):
    # 提取数据...
    content = data["choices"][0]["message"]["content"]
    finish_reason = data["choices"][0]["finish_reason"]
    
    # 原先的处理逻辑...
    formatted_response = {
        "id": data["id"],
        "object": "chat.completion",
        "created": 0,
        "model": data["model"],
        "usage": data["usage"],
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }]
    }

    return formatted_response


# 白名单版本
def format_response_white(data):
    # 提取数据...
    content = data["choices"][0]["message"]["content"]
    finish_reason = data["choices"][0]["finish_reason"]

    # 创建一个新的数据结构，只包含需要的字段...
    formatted_response = {
        "id": data["id"],
        "object": "chat.completion",
        "created": 0,
        "model": data["model"],
        "usage": data["usage"],
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
            },
            "finish_reason": finish_reason,
        }],
    }

    return formatted_response


# 根据设置选择使用哪个函数
def process_data(data, filter_mode='white'):
    if filter_mode == 'white':
        return format_response_white(data)
    else:  # 如果filter_mode设置为'black'
        return format_response_black(data)


# 旧的通用函数入口现在默认使用白名单版本
def format_response(data):
    return format_response_white(data)


# 日志级别处理器
@app.route('/admin/log_level', methods=['PATCH'])
def log_level_handler():
    data = request.get_json()
    if 'log_level' not in data:
        return 'Log level 未提供', 400

    log_level = data['log_level']
    # 检查 log_level 是否是有效的日志级别
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if not isinstance(log_level, str) or log_level not in valid_log_levels:
        return '无效的 Log Level', 400

    logger.setLevel(log_level)
    return 'Log Level 已更新', 200

# 如果这个脚本是作为主程序运行
if __name__ == '__main__':
    # 运行Flask应用，设置为非调试模式，让应用在任何公共IP上运行，并在8080端口上监听请求
    app.run(debug=True, host='0.0.0.0', port=8080)