from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import os
import json
import requests
import logging
import uuid
import configparser
import re


# 创建 ConfigParser 实例
config = configparser.ConfigParser()

# 读取 config.ini 文件
config.read('config.ini', encoding='utf-8')


# 获取配置项的值
ADMIN_PASSWORD = config.get('DEFAULT', 'ADMIN_PASSWORD', fallback='TotallySecurePassword')
log_level = config.get('DEFAULT', 'LOG_LEVEL', fallback='INFO')
log_file = config.get('DEFAULT', 'LOG_FILE', fallback='app.log')
log_enabled = config.getboolean('DEFAULT', 'LOG_ENABLED', fallback=True)

API_KEYS = {}
with open("api_keys.txt", "r") as file:
    for line in file:
        key = line.strip()
        if key != "":
            API_KEYS["Bearer " + key] = True

# 创建一个用于将日志输出到文件的处理器
handler = logging.FileHandler(log_file)

# 创建一个定义日志信息格式的格式化程序
formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')

# 为处理器设置格式化程序
handler.setFormatter(formatter)

# 创建Logger对象，并为每个Logger设置处理器和级别
LOGGERS = {
    'send_request': logging.getLogger('send_request'),
    'received_data': logging.getLogger('received_data'),
    'final_response': logging.getLogger('final_response'),
    'process_request': logging.getLogger('process_request'),
}

# 遍历并设置Logger的处理器和级别
for logger_name, logger in LOGGERS.items():
    logger.addHandler(handler)
    logger.setLevel(log_level)

# 根据日志开关启用或禁用日志记录
if not log_enabled:
    for logger in LOGGERS.values():
        logger.disabled = True

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
        self.tokens = tokens

        # 保存令牌到文件
        with open('access_tokens.json', 'w') as f:
            json.dump(tokens, f)

    # 获取令牌方法
    def get_token(self):
        if not self.tokens:
            return ""

        token = self.tokens.pop(0)
        return token


# 创建一个新的Flask应用
app = Flask(__name__)

CORS(app)

# 初始化访问令牌
ACCESS_TOKENS = AccessToken(["token1", "token2", "token3"])


# 创建全局的ThreadPoolExecutor实例
executor = ThreadPoolExecutor(max_workers=10)

# 发送请求函数
def send_request(chatgpt_request, access_token):
    url = config.get('DEFAULT', 'API_URL', fallback='https://ai.fakeopen.com/api/conversation')
    user_agent = config.get('DEFAULT', 'USER_AGENT', fallback='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36')

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': user_agent,
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


# 处理请求的函数
def process_request(data):
    # 转换API请求
    chatgpt_request = convert_api_request(data)
    LOGGERS['process_request'].info('转换API请求完成')

    # 获取访问令牌
    access_token = ACCESS_TOKENS.get_token()
    LOGGERS['process_request'].info('获取访问令牌完成')

    # 发送请求
    response = send_request(chatgpt_request, access_token)
    LOGGERS['process_request'].info('发送请求完成')

    # 释放访问令牌
    if access_token:
        ACCESS_TOKENS.tokens.append(access_token)
    LOGGERS['process_request'].info('释放访问令牌完成')

    # 处理返回的数据
    final_message = None
    for line in response.content.decode().split("\n"):
        if line.startswith("data:"):
            message = json.loads(line[5:])  # 移除 "data:" 并解析 JSON
            if message["message"]["status"] == "finished_successfully" and message["message"]["author"]["role"] == "assistant":
                final_message = message
                break
    LOGGERS['process_request'].info('处理返回的数据完成')
    
    LOGGERS['process_request'].info('最后的消息1: %s', final_message)

    if final_message is None:
        LOGGERS['process_request'].error('未找到有效的返回信息')
        return None    
    
    LOGGERS['process_request'].info('最后的消息2: %s', final_message)

    # 使用新的格式化函数

    
    LOGGERS['process_request'].info('About to call format_response_white')
    #formatted_response = format_response(final_message)
    LOGGERS['process_request'].info('Finished calling format_response_white')


    LOGGERS['process_request'].info('格式化响应完成')

    #return formatted_response
    return final_message


def request_handler(data):
    # 提交任务给ThreadPoolExecutor执行
    future = executor.submit(process_request, data)

    result = future.result()  # 获取任务结果

    LOGGERS['received_data'].info('req-debug-result: %s', result)
    # 处理返回的数据
    processed_data, rich_text = process_json_data(result)
    
    LOGGERS['received_data'].info('req-debug-processed_data: %s', processed_data)
    LOGGERS['received_data'].info('req-debug-rich: %s', rich_text)

    # 使用新的格式化函数
    formatted_response = format_response_white(processed_data, rich_text)
    LOGGERS['received_data'].info('req-debug-formatted_response: %s', formatted_response)
    return formatted_response


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
    formatted_response = request_handler(data)
    # 返回处理后的数据
    LOGGERS['final_response'].info('最终响应: %s', formatted_response)
    return json.dumps(formatted_response), 200


# 黑名单版本
def format_response_black(data):
    # 提取数据...
    message = data["message"]
    content = message["content"]["parts"][0]
    status = message["status"]
    model_slug = message["metadata"]["model_slug"]

    # 原先的处理逻辑...
    formatted_response = {
        "id": message["id"],
        "object": "chat.completion",
        "created": int(message["create_time"]),
        "model": model_slug,
        "choices": [{
            "message": {
                "role": message["author"]["role"],
                "content": content
            },
            "finish_reason": status
        }]
    }

    return formatted_response


def format_response_white(data, rich_text):
    LOGGERS['process_request'].info('UP!!!!')
    LOGGERS['received_data'].info('data-DEBUG: %s', data)  # 将data信息打印到日志中
    # 提取数据...
    content = data["message"]["content"]["parts"][0]
    finish_reason = data["message"]["metadata"]["finish_details"]["type"]
    created = int(data["message"]["create_time"])

    # 创建新的数据结构，包含处理后的内容
    formatted_response = {
        "id": data["message"]["id"],
        "object": "chat.completion",
        "created": created,
        "model": data["message"]["metadata"]["model_slug"],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        },
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": ""  # 先假设content为空
            },
            "finish_reason": finish_reason,
        }],
    }

    # 将formatted_response转换为字符串
    Out0 = json.dumps(formatted_response)

    # 定位'"content": "'的位置
    content_start_index = Out0.find('"content": "')
    if content_start_index == -1:
        return formatted_response  # 如果找不到'"content": "'，则直接返回原始数据

    # 将'"content": "'之前的所有字符移动到Out1
    Out1 = Out0[:content_start_index + 12]

    # 将'"content": "'之后的所有字符移动到Out2
    Out2 = Out0[content_start_index + 12:]

    # 将Out1、rich_text和Out2并起来形成Out3
    Out3 = Out1 + rich_text + Out2

    # 将Out3转换回JSON
    formatted_response = json.loads(Out3)

    # 记录存放的富文本数据
    LOGGERS['received_data'].info('存放的富文本数据: %s', rich_text)

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

    for logger in LOGGERS.values():
        logger.setLevel(log_level)
    return 'Log Level 已更新', 200

def process_json_data_a(data):
    # 将数据转换为字符串
    LOGGERS['received_data'].info('str-debug-data: %s', data)
    str0 = json.dumps(data)
    LOGGERS['received_data'].info('str0-debug: %s', str0)

    # 初始化字符串变量
    str1 = ""
    str2 = ""
    str3 = ""

    # 定位"parts": ["的位置
    parts_start_index = str0.find('"parts": ["')
    if parts_start_index == -1:
        return data, ""  # 如果找不到"parts": ["，则直接返回原始数据和空字符串

    # 将"parts": ["之前的所有字符移动到str1
    str1 = str0[:parts_start_index + 11]
    LOGGERS['received_data'].info('str1: %s', str1)
    # 定位"], "status": "finished_successfully"的位置
    status_start_index = str0.find('"], "status": "finished_successfully"')
    LOGGERS['received_data'].info('status_start_index: %s', status_start_index)
    if status_start_index == -1:
        return data, ""  # 如果找不到"], "status": "finished_successfully"，则直接返回原始数据和空字符串

    # 将"], "status": "finished_successfully"之前的所有字符移动到str2
    str2 = str0[parts_start_index + 11:status_start_index]
    LOGGERS['received_data'].info('str2: %s', str2)

    # 将"], "status": "finished_successfully"之后的所有字符移动到str3
    str3 = str0[status_start_index:]
    LOGGERS['received_data'].info('str3: %s', str3)
    # 将str1和str3并起来形成str4
    str4 = str1 + '"]' + str3
    LOGGERS['received_data'].info('str4: %s', str4)
    
    # 将str4转换回JSON
    processed_data = json.loads(str4)
    LOGGERS['received_data'].info('str0: %s', str0)
    LOGGERS['received_data'].info('str1: %s', str1)
    LOGGERS['received_data'].info('str2: %s', str2)
    LOGGERS['received_data'].info('str3: %s', str3)
    LOGGERS['received_data'].info('str4: %s', str4)
    LOGGERS['received_data'].info('processed_data: %s', processed_data)

    return processed_data, str2



def process_json_data_b(data):
    # 将输入数据转换为 JSON 字符串
    str0 = json.dumps(data)
    LOGGERS['received_data'].info('str0-debug: %s', str0)

    start_marker = '"parts": ["'
    end_marker = '"], "status": "finished_successfully"'

    # 找到 "parts": [" 的位置
    parts_start_index = str0.find(start_marker)
    if parts_start_index == -1:
        return data, ""  # 如果找不到"parts": ["，则直接返回原始数据和空字符串

    # "parts": ["之后的起始位置
    start_pos = parts_start_index + len(start_marker)

    # 从 "parts": [" 后找到 "], "status": "finished_successfully" 的位置
    status_start_index = str0.find(end_marker, start_pos)
    if status_start_index == -1:
        return data, ""  # 如果找不到"], "status": "finished_successfully"，则直接返回原始数据和空字符串

    # 截取三段字符串
    str1 = str0[:start_pos]  # "parts": ["之前的所有字符
    str2 = str0[start_pos:status_start_index]  # "parts": [" 和 "], "status": "finished_successfully" 之间的字符串
    str3 = str0[status_start_index:]  # "], "status": "finished_successfully"之后的所有字符

    # 合并第一段和第三段字符串
    str4 = str1 + str3
    LOGGERS['received_data'].info('str4: %s', str4)

    # 转换回 JSON 格式
    processed_data = json.loads(str4)

    # 输出日志
    LOGGERS['received_data'].info('str1: %s', str1)
    LOGGERS['received_data'].info('str2: %s', str2)
    LOGGERS['received_data'].info('str3: %s', str3)
    LOGGERS['received_data'].info('processed_data: %s', processed_data)

    return processed_data, str2  # 返回处理后的 JSON 数据和 "parts" 中的内容

def process_json_data(data):
    # 将输入数据转换为 JSON 字符串
    str0 = json.dumps(data)
    LOGGERS['received_data'].info('str0-debug: %s', str0)

    # 使用正则表达式匹配 "parts" 字段和它的内容
    pattern = r'"parts": \[.*?\], "status": "finished_successfully"'
    match = re.search(pattern, str0)

    if match is None:
        return data, ""  # 如果找不到 "parts" 字段，直接返回原始数据和空字符串

    # 获取 "parts" 字段的内容
    parts_content = match.group(0)[10:-1]

    # 删除 "parts" 字段
    str1 = re.sub(pattern, '', str0)
    LOGGERS['received_data'].info('str1: %s', str1)

    # 转换回 JSON 格式
    processed_data = json.loads(str1)

    LOGGERS['received_data'].info('processed_data: %s', processed_data)

    return processed_data, parts_content  # 返回处理后的 JSON 数据和 "parts" 中的内容





# 如果这个脚本是作为主程序运行
if __name__ == '__main__':
    # 运行Flask应用，设置为非调试模式，让应用在任何公共IP上运行，并在8080端口上监听请求
    app.run(debug=True, host='0.0.0.0', port=8080)
