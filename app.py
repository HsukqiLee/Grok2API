import os
import json
import uuid
import time
import base64
import sys
import inspect
import secrets
from loguru import logger
from pathlib import Path

import requests # For PicGo/TUMY and get_statsig_id
from flask import Flask, request, Response, jsonify, stream_with_context, render_template, redirect, session
from curl_cffi import requests as curl_requests
from werkzeug.middleware.proxy_fix import ProxyFix

import struct # New import for statsig_id generation
import hashlib # New import for statsig_id generation
import random # New import for statsig_id generation

class Logger:
    def __init__(self, level="INFO", colorize=True, format=None):
        logger.remove()

        if format is None:
            format = (
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{extra[filename]}</cyan>:<cyan>{extra[function]}</cyan>:<cyan>{extra[lineno]}</cyan> | "
                "<level>{message}</level>"
            )

        logger.add(
            sys.stderr,
            level=level,
            format=format,
            colorize=colorize,
            backtrace=True,
            diagnose=True
        )

        self.logger = logger

    def _get_caller_info(self):
        frame = inspect.currentframe()
        try:
            caller_frame = frame.f_back.f_back
            full_path = caller_frame.f_code.co_filename
            function = caller_frame.f_code.co_name
            lineno = caller_frame.f_lineno

            filename = os.path.basename(full_path)

            return {
                'filename': filename,
                'function': function,
                'lineno': lineno
            }
        finally:
            del frame

    def info(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"[{source}] {message}")

    def error(self, message, source="API"):
        caller_info = self._get_caller_info()

        if isinstance(message, Exception):
            self.logger.bind(**caller_info).exception(f"[{source}] {str(message)}")
        else:
            self.logger.bind(**caller_info).error(f"[{source}] {message}")

    def warning(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).warning(f"[{source}] {message}")

    def debug(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).debug(f"[{source}] {message}")

    async def request_logger(self, request):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"请求: {request.method} {request.path}", "Request")

logger = Logger(level="INFO")
DATA_DIR = Path("/data")

if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG = {
    "MODELS": {
        'grok-2': 'grok-latest',
        'grok-2-imageGen': 'grok-latest',
        'grok-2-search': 'grok-latest',
        "grok-3": "grok-3",
        "grok-3-search": "grok-3",
        "grok-3-imageGen": "grok-3",
        "grok-3-deepsearch": "grok-3",
        "grok-3-deepersearch": "grok-3",
        "grok-3-reasoning": "grok-3"
    },
    "API": {
        "IS_TEMP_CONVERSATION": os.environ.get("IS_TEMP_CONVERSATION", "true").lower() == "true",
        "IS_CUSTOM_SSO": os.environ.get("IS_CUSTOM_SSO", "false").lower() == "true",
        "BASE_URL": "https://grok.com",
        "API_KEY": os.environ.get("API_KEY", "sk-123456"),
        "SIGNATURE_COOKIE": None,
        "PICGO_KEY": os.environ.get("PICGO_KEY") or None,
        "TUMY_KEY": os.environ.get("TUMY_KEY") or None,
        "RETRY_TIME": 1000,
        "PROXY": os.environ.get("PROXY") or None
    },
    "ADMIN": {
        "MANAGER_SWITCH": os.environ.get("MANAGER_SWITCH") or None,
        "PASSWORD": os.environ.get("ADMINPASSWORD") or None
    },
    "SERVER": {
        "COOKIE": None,
        "CF_CLEARANCE":os.environ.get("CF_CLEARANCE") or None,
        "PORT": int(os.environ.get("PORT", 5200))
    },
    "RETRY": {
        "RETRYSWITCH": False,
        "MAX_ATTEMPTS": 2
    },
    "TOKEN_STATUS_FILE": str(DATA_DIR / "token_status.json"),
    "SHOW_THINKING": os.environ.get("SHOW_THINKING") == "true",
    "IS_THINKING": False,
    "IS_IMG_GEN": False,
    "IS_IMG_GEN2": False,
    "ISSHOW_SEARCH_RESULTS": os.environ.get("ISSHOW_SEARCH_RESULTS", "true").lower() == "true"
}


DEFAULT_HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Content-Type': 'text/plain;charset=UTF-8',
    'Connection': 'keep-alive',
    'Origin': 'https://grok.com',
    'Priority': 'u=1, i',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Sec-Ch-Ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"macOS"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Baggage': 'sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c',
    'x-statsig-id': 'ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGlsZE5vZGVzJyk='# 暂用固定x-statsig-id，失效再看
}

class AuthTokenManager:
    def __init__(self):
        self.token_model_map = {}
        self.expired_tokens = set()
        self.token_status_map = {}

        self.model_config = {
            "grok-2": {
                "RequestFrequency": 30,
                "ExpirationTime": 1 * 60 * 60 * 1000  # 1小时
            },
            "grok-3": {
                "RequestFrequency": 20,
                "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
            },
            "grok-3-deepsearch": {
                "RequestFrequency": 10,
                "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
            },
            "grok-3-deepersearch": {
                "RequestFrequency": 3,
                "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
            },
            "grok-3-reasoning": {
                "RequestFrequency": 10,
                "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
            }
        }
        self.token_reset_switch = False
        self.token_reset_timer = None
        self.load_token_status() # 加载令牌状态
    def save_token_status(self):
        try:
            with open(CONFIG["TOKEN_STATUS_FILE"], 'w', encoding='utf-8') as f:
                json.dump(self.token_status_map, f, indent=2, ensure_ascii=False)
            logger.info("令牌状态已保存到配置文件", "TokenManager")
        except Exception as error:
            logger.error(f"保存令牌状态失败: {str(error)}", "TokenManager")

    def load_token_status(self):
        try:
            token_status_file = Path(CONFIG["TOKEN_STATUS_FILE"])
            if token_status_file.exists():
                with open(token_status_file, 'r', encoding='utf-8') as f:
                    self.token_status_map = json.load(f)
                logger.info("已从配置文件加载令牌状态", "TokenManager")
        except Exception as error:
            logger.error(f"加载令牌状态失败: {str(error)}", "TokenManager")
    def add_token(self, token,isinitialization=False):
        sso = token.split("sso=")[1].split(";")[0]
        for model in self.model_config.keys():
            if model not in self.token_model_map:
                self.token_model_map[model] = []
            if sso not in self.token_status_map:
                self.token_status_map[sso] = {}

            existing_token_entry = next((entry for entry in self.token_model_map[model] if entry["token"] == token), None)

            if not existing_token_entry:
                self.token_model_map[model].append({
                    "token": token,
                    "RequestCount": 0,
                    "AddedTime": int(time.time() * 1000),
                    "StartCallTime": None
                })

                if model not in self.token_status_map[sso]:
                    self.token_status_map[sso][model] = {
                        "isValid": True,
                        "invalidatedTime": None,
                        "totalRequestCount": 0
                    }
        if not isinitialization:
            self.save_token_status()

    def set_token(self, token):
        models = list(self.model_config.keys())
        self.token_model_map = {model: [{
            "token": token,
            "RequestCount": 0,
            "AddedTime": int(time.time() * 1000),
            "StartCallTime": None
        }] for model in models}

        sso = token.split("sso=")[1].split(";")[0]
        self.token_status_map[sso] = {model: {
            "isValid": True,
            "invalidatedTime": None,
            "totalRequestCount": 0
        } for model in models}

    def delete_token(self, token):
        try:
            sso = token.split("sso=")[1].split(";")[0]
            for model in self.token_model_map:
                self.token_model_map[model] = [entry for entry in self.token_model_map[model] if entry["token"] != token]

            if sso in self.token_status_map:
                del self.token_status_map[sso]

            self.save_token_status()

            logger.info(f"令牌已成功移除: {token}", "TokenManager")
            return True
        except Exception as error:
            logger.error(f"令牌删除失败: {str(error)}")
            return False
    def reduce_token_request_count(self, model_id, count):
        try:
            normalized_model = self.normalize_model_name(model_id)

            if normalized_model not in self.token_model_map:
                logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
                return False

            if not self.token_model_map[normalized_model]:
                logger.error(f"模型 {normalized_model} 没有可用的token", "TokenManager")
                return False

            token_entry = self.token_model_map[normalized_model][0]

            # 确保RequestCount不会小于0
            new_count = max(0, token_entry["RequestCount"] - count)
            reduction = token_entry["RequestCount"] - new_count

            token_entry["RequestCount"] = new_count

            # 更新token状态
            if token_entry["token"]:
                sso = token_entry["token"].split("sso=")[1].split(";")[0]
                if sso in self.token_status_map and normalized_model in self.token_status_map[sso]:
                    self.token_status_map[sso][normalized_model]["totalRequestCount"] = max(
                        0,
                        self.token_status_map[sso][normalized_model]["totalRequestCount"] - reduction
                    )
            return True

        except Exception as error:
            logger.error(f"重置校对token请求次数时发生错误: {str(error)}", "TokenManager")
            return False
    def get_next_token_for_model(self, model_id, is_return=False):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map or not self.token_model_map[normalized_model]:
            return None

        token_entry = self.token_model_map[normalized_model][0]
        if is_return:
            return token_entry["token"]

        if token_entry:
            if token_entry["StartCallTime"] is None:
                token_entry["StartCallTime"] = int(time.time() * 1000)

            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True

            token_entry["RequestCount"] += 1

            if token_entry["RequestCount"] > self.model_config[normalized_model]["RequestFrequency"]:
                self.remove_token_from_model(normalized_model, token_entry["token"])
                next_token_entry = self.token_model_map[normalized_model][0] if self.token_model_map[normalized_model] else None
                return next_token_entry["token"] if next_token_entry else None

            sso = token_entry["token"].split("sso=")[1].split(";")[0]
            if sso in self.token_status_map and normalized_model in self.token_status_map[sso]:
                if token_entry["RequestCount"] == self.model_config[normalized_model]["RequestFrequency"]:
                    self.token_status_map[sso][normalized_model]["isValid"] = False
                    self.token_status_map[sso][normalized_model]["invalidatedTime"] = int(time.time() * 1000)
                self.token_status_map[sso][normalized_model]["totalRequestCount"] += 1

                self.save_token_status()

            return token_entry["token"]

        return None

    def remove_token_from_model(self, model_id, token):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map:
            logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
            return False

        model_tokens = self.token_model_map[normalized_model]
        token_index = next((i for i, entry in enumerate(model_tokens) if entry["token"] == token), -1)

        if token_index != -1:
            removed_token_entry = model_tokens.pop(token_index)
            self.expired_tokens.add((
                removed_token_entry["token"],
                normalized_model,
                int(time.time() * 1000)
            ))

            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True

            logger.info(f"模型{model_id}的令牌已失效，已成功移除令牌: {token}", "TokenManager")
            return True

        logger.error(f"在模型 {normalized_model} 中未找到 token: {token}", "TokenManager")
        return False

    def get_expired_tokens(self):
        return list(self.expired_tokens)

    def normalize_model_name(self, model):
        if model.startswith('grok-') and 'deepsearch' not in model and 'reasoning' not in model:
            return '-'.join(model.split('-')[:2])
        return model

    def get_token_count_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return len(self.token_model_map.get(normalized_model, []))

    def get_remaining_token_request_capacity(self):
        remaining_capacity_map = {}

        for model in self.model_config.keys():
            model_tokens = self.token_model_map.get(model, [])
            model_request_frequency = self.model_config[model]["RequestFrequency"]

            total_used_requests = sum(token_entry.get("RequestCount", 0) for token_entry in model_tokens)

            remaining_capacity = (len(model_tokens) * model_request_frequency) - total_used_requests
            remaining_capacity_map[model] = max(0, remaining_capacity)

        return remaining_capacity_map

    def get_token_array_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return self.token_model_map.get(normalized_model, [])

    def start_token_reset_process(self):
        def reset_expired_tokens():
            now = int(time.time() * 1000)

            tokens_to_remove = set()
            for token_info in self.expired_tokens:
                token, model, expired_time = token_info
                expiration_time = self.model_config[model]["ExpirationTime"]

                if now - expired_time >= expiration_time:
                    if not any(entry["token"] == token for entry in self.token_model_map.get(model, [])):
                        if model not in self.token_model_map:
                            self.token_model_map[model] = []

                        self.token_model_map[model].append({
                            "token": token,
                            "RequestCount": 0,
                            "AddedTime": now,
                            "StartCallTime": None
                        })

                    sso = token.split("sso=")[1].split(";")[0]
                    if sso in self.token_status_map and model in self.token_status_map[sso]:
                        self.token_status_map[sso][model]["isValid"] = True
                        self.token_status_map[sso][model]["invalidatedTime"] = None
                        self.token_status_map[sso][model]["totalRequestCount"] = 0

                    tokens_to_remove.add(token_info)

            self.expired_tokens -= tokens_to_remove

            for model in self.model_config.keys():
                if model not in self.token_model_map:
                    continue

                for token_entry in self.token_model_map[model]:
                    if not token_entry.get("StartCallTime"):
                        continue

                    expiration_time = self.model_config[model]["ExpirationTime"]
                    if now - token_entry["StartCallTime"] >= expiration_time:
                        sso = token_entry["token"].split("sso=")[1].split(";")[0]
                        if sso in self.token_status_map and model in self.token_status_map[sso]:
                            self.token_status_map[sso][model]["isValid"] = True
                            self.token_status_map[sso][model]["invalidatedTime"] = None
                            self.token_status_map[sso][model]["totalRequestCount"] = 0

                        token_entry["RequestCount"] = 0
                        token_entry["StartCallTime"] = None

        import threading
        # 启动一个线程执行定时任务，每小时执行一次
        def run_timer():
            while True:
                reset_expired_tokens()
                time.sleep(3600)

        timer_thread = threading.Thread(target=run_timer)
        timer_thread.daemon = True
        timer_thread.start()

    def get_all_tokens(self):
        all_tokens = set()
        for model_tokens in self.token_model_map.values():
            for entry in model_tokens:
                all_tokens.add(entry["token"])
        return list(all_tokens)
    def get_current_token(self, model_id):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map or not self.token_model_map[normalized_model]:
            return None

        token_entry = self.token_model_map[normalized_model][0]
        return token_entry["token"]

    def get_token_status_map(self):
        return self.token_status_map

class Utils:
    # 添加新的类属性
    key = None
    animation_key = None
    random_keyword = "bird"
    random_number = 42

    @staticmethod
    def organize_search_results(search_results):
        if not search_results or 'results' not in search_results:
            return ''
        results = search_results['results']
        formatted_results = []
        for index, result in enumerate(results):
            title = result.get('title', '未知标题')
            url = result.get('url', '#')
            preview = result.get('preview', '无预览内容')
            formatted_result = f"\r\n<details><summary>资料[{index}]: {title}</summary>\r\n{preview}\r\n\n[Link]({url})\r\n</details>"
            formatted_results.append(formatted_result)
        return '\n\n'.join(formatted_results)

    @staticmethod
    def create_auth_headers(model, is_return=False):
        return token_manager.get_next_token_for_model(model, is_return)

    @staticmethod
    def get_proxy_options():
        proxy = CONFIG["API"]["PROXY"]
        proxy_options = {}
        if proxy:
            logger.info(f"使用代理: {proxy}", "Server")

            if proxy.startswith("socks5://"):
                proxy_options["proxy"] = proxy

                if '@' in proxy:
                    auth_part = proxy.split('@')[0].split('://')[1]
                    if ':' in auth_part:
                        username, password = auth_part.split(':')
                        proxy_options["proxy_auth"] = (username, password)
            else:
                proxy_options["proxies"] = {"https": proxy, "http": proxy}
        return proxy_options

    @staticmethod
    def generate_statsig_id():
        """生成符合格式的 x-statsig-id"""
        try:
            # 1. 生成48字节的meta content
            meta_templates = [
                bytes.fromhex("30902da2569a6aa4b92bae5a1fb941ac30791cb9130dda57476bb7646d15a263dbfc84103acb2644c83e4ddb2451734d"),
                bytes.fromhex("40a02db3679b7bb5ca3cbf6b2fca52bd41892dca241eeb68587cc8757e26b374ecfd95214bdc3755d94f5eec3562845e"),
                bytes.fromhex("50b03ec4789c8cc6db4dc07c3fdb63ce52993edb352ffc79698dd9868f37c485fdfea6325ced4866ea5f6ffd4673956f") # Corrected hex string
            ]

            # 随机选择一个模板或生成新的
            if random.random() < 0.7:  # 70%的概率使用模板
                meta_content = random.choice(meta_templates)
            else:
                # 生成随机的48字节
                meta_content = bytes([random.randint(0, 255) for _ in range(48)])

            # 2. 生成时间戳（4字节）
            current_timestamp = int(time.time())
            relative_timestamp = current_timestamp - 1682924400
            timestamp_bytes = struct.pack('<I', relative_timestamp)  # 小端序

            # 3. 生成SHA256片段（16字节）
            # 模拟指纹信息的哈希
            fingerprint_data = f"POST!/rest/app-chat/conversations/new!{relative_timestamp}"
            fingerprint_data += "screen:2560x1440,platform:MacIntel,language:zh-CN"
            hash_obj = hashlib.sha256(fingerprint_data.encode('utf-8'))
            hash_bytes = hash_obj.digest()[:16]

            # 4. 固定值（1字节）
            fixed_byte = b'\x03'

            # 5. 组合所有部分（69字节）
            combined = meta_content + timestamp_bytes + hash_bytes + fixed_byte

            # 6. 生成随机异或密钥（1字节）
            xor_key = random.randint(0x10, 0xF0)

            # 7. 异或加密
            encrypted = bytes([b ^ xor_key for b in combined])

            # 8. 添加密钥到开头（总共70字节）
            final_data = bytes([xor_key]) + encrypted

            # 9. Base64编码
            statsig_id = base64.b64encode(final_data).decode('utf-8')

            # 移除padding（如果有）
            statsig_id = statsig_id.rstrip('=')

            return statsig_id

        except Exception as e:
            logger.error(f"生成 statsig id 时发生错误: {str(e)}", "Utils")
            # 返回一个已知有效的ID作为后备
            fallback_ids = [
                "FiaGO7RAjHyyrz24TAmvV7ombwqvBRvMQVF9oXJ7A7R1zeqSBizdMFLeKFvNMkdlW2ov8RWn675EmkrfoV8U08Oi9tMkFQ",
                "799/wk25dYVLVsRBtfBWrkPflvNW/OI1uKiEWIuC+k2MNBNr/9Ukyasn0aI0y76cohjWCOwsSQjx0BhUxzH1LAarvhxP7A",
                "xfVV6GeTX69hfO5rn9p8hGn1vNl81sgfkoKucqGo0GemHjlB1f8O44EN+4ge4ZS2iBeRIsaPUtakrUDHhmP8urJomXb4xg",
                "Lx+/Ao15tUWLlgSBdTCWboMfVjOWPCL1eGhEmEtCOo1M9NOrPxXkCWvnEWL0C35cYnERyCxEF1ZQ8vVf1jv/7IdmtV4bLA"
            ]
            return random.choice(fallback_ids)

    @staticmethod
    def get_statsig_id():
        """获取 statsig id - 优先尝试API，失败则本地生成"""
        try:
            # 先尝试从API获取 https://rui.soundai.ee/x.php
            response = requests.get("https://rui.soundai.ee/x.php", timeout=3)
            if response.status_code == 200:
                data = response.json()
                # Check if 'x_statsig_id' key exists and is not empty or None
                statsig_id_from_api = data.get("x_statsig_id")
                if statsig_id_from_api: 
                    return statsig_id_from_api
        except Exception as e: # Catch specific exceptions if possible, e.g., requests.exceptions.RequestException
            logger.warning(f"从API获取statsig_id失败: {str(e)}. 将本地生成.", "Utils")
            pass # Fall through to local generation

        # 如果API失败或返回无效ID，本地生成
        return Utils.generate_statsig_id()

class GrokApiClient:
    def __init__(self, model_id):
        if model_id not in CONFIG["MODELS"]:
            raise ValueError(f"不支持的模型: {model_id}")
        self.model_id = CONFIG["MODELS"][model_id]

    def process_message_content(self, content):
        if isinstance(content, str):
            return content
        return None

    def get_image_type(self, base64_string):
        mime_type = 'image/jpeg'
        if 'data:image' in base64_string:
            import re
            matches = re.search(r'data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,', base64_string)
            if matches:
                mime_type = matches.group(1)

        extension = mime_type.split('/')[1]
        file_name = f"image.{extension}"

        return {
            "mimeType": mime_type,
            "fileName": file_name
        }
    def upload_base64_file(self, message, model):
        try:
            message_base64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
            upload_data = {
                "fileName": "message.txt",
                "fileMimeType": "text/plain",
                "content": message_base64
            }

            logger.info("发送文字文件请求", "Server")
            cookie = f"{Utils.create_auth_headers(model, True)};{CONFIG['SERVER']['CF_CLEARANCE']}"
            proxy_options = Utils.get_proxy_options()
            response = curl_requests.post(
                "https://grok.com/rest/app-chat/upload-file",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie": cookie,
                    "x-statsig-id": Utils.get_statsig_id(),
                    "x-xai-request-id": str(uuid.uuid4())
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options
            )

            if response.status_code != 200:
                logger.error(f"上传文件失败,状态码:{response.status_code}", "Server")
                raise Exception(f"上传文件失败,状态码:{response.status_code}")

            result = response.json()
            logger.info(f"上传文件成功: {result}", "Server")
            return result.get("fileMetadataId", "")

        except Exception as error:
            logger.error(str(error), "Server")
            # Retain original error message if possible, or a more generic one
            if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
                 raise Exception(f"上传文件失败,状态码:{error.response.status_code}")
            raise Exception("上传文件失败")


    def upload_base64_image(self, base64_data, url):
        try:
            if 'data:image' in base64_data:
                image_buffer = base64_data.split(',')[1]
            else:
                image_buffer = base64_data

            image_info = self.get_image_type(base64_data)
            mime_type = image_info["mimeType"]
            file_name = image_info["fileName"]

            upload_data = {
                "rpc": "uploadFile",
                "req": {
                    "fileName": file_name,
                    "fileMimeType": mime_type,
                    "content": image_buffer
                }
            }

            logger.info("发送图片请求", "Server")

            proxy_options = Utils.get_proxy_options()
            response = curl_requests.post(
                url,
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie": CONFIG["SERVER"]['COOKIE'],
                    "x-statsig-id": Utils.get_statsig_id(),
                    "x-xai-request-id": str(uuid.uuid4())
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options
            )

            if response.status_code != 200:
                logger.error(f"上传图片失败,状态码:{response.status_code}", "Server")
                return ''

            result = response.json()
            logger.info(f"上传图片成功: {result}", "Server")
            return result.get("fileMetadataId", "")

        except Exception as error:
            logger.error(str(error), "Server")
            return ''

    def prepare_chat_request(self, request):
        if ((request["model"] == 'grok-2-imageGen' or request["model"] == 'grok-3-imageGen') and
            not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"] and
            request.get("stream", False)):
            raise ValueError("该模型流式输出需要配置PICGO或者TUMY图床密钥!")

        todo_messages = request["messages"]
        if request["model"] in ['grok-2-imageGen', 'grok-3-imageGen', 'grok-3-deepsearch']:
            last_message = todo_messages[-1]
            if last_message["role"] != 'user':
                raise ValueError('此模型最后一条消息必须是用户消息!')
            todo_messages = [last_message]
        file_attachments = []
        messages = ''
        last_role = None
        last_content = ''
        message_length = 0
        convert_to_file = False
        last_message_content = ''
        search = request["model"] in ['grok-2-search', 'grok-3-search']
        deepsearchPreset = ''
        if request["model"] == 'grok-3-deepsearch':
            deepsearchPreset = 'default'
        elif request["model"] == 'grok-3-deepersearch':
            deepsearchPreset = 'deeper'

        def remove_think_tags(text):
            import re
            text = re.sub(r'<think>[\s\S]*?<\/think>', '', text).strip()
            text = re.sub(r'!\[image\]\(data:.*?base64,.*?\)', '[图片]', text)
            return text

        def process_content(content):
            if isinstance(content, list):
                text_content = ''
                for item in content:
                    if item["type"] == 'image_url':
                        text_content += ("[图片]" if not text_content else '\n[图片]')
                    elif item["type"] == 'text':
                        text_content += (remove_think_tags(item["text"]) if not text_content else '\n' + remove_think_tags(item["text"]))
                return text_content
            elif isinstance(content, dict) and content is not None:
                if content["type"] == 'image_url':
                    return "[图片]"
                elif content["type"] == 'text':
                    return remove_think_tags(content["text"])
            return remove_think_tags(self.process_message_content(content))
        for current in todo_messages:
            role = 'assistant' if current["role"] == 'assistant' else 'user'
            is_last_message = current == todo_messages[-1]

            if is_last_message and "content" in current:
                if isinstance(current["content"], list):
                    for item in current["content"]:
                        if item["type"] == 'image_url':
                            processed_image = self.upload_base64_image(
                                item["image_url"]["url"],
                                f"{CONFIG['API']['BASE_URL']}/api/rpc"
                            )
                            if processed_image:
                                file_attachments.append(processed_image)
                elif isinstance(current["content"], dict) and current["content"].get("type") == 'image_url':
                    processed_image = self.upload_base64_image(
                        current["content"]["image_url"]["url"],
                        f"{CONFIG['API']['BASE_URL']}/api/rpc"
                    )
                    if processed_image:
                        file_attachments.append(processed_image)


            text_content = process_content(current.get("content", ""))
            if is_last_message and convert_to_file:
                last_message_content = f"{role.upper()}: {text_content or '[图片]'}\n"
                continue
            if text_content or (is_last_message and file_attachments):
                if role == last_role and text_content:
                    last_content += '\n' + text_content
                    messages = messages[:messages.rindex(f"{role.upper()}: ")] + f"{role.upper()}: {last_content}\n"
                else:
                    messages += f"{role.upper()}: {text_content or '[图片]'}\n"
                    last_content = text_content
                    last_role = role
            message_length += len(messages)
            if message_length >= 40000:
                convert_to_file = True

        if convert_to_file:
            file_id = self.upload_base64_file(messages, request["model"])
            if file_id:
                file_attachments.insert(0, file_id)
            messages = last_message_content.strip()
        if messages.strip() == '':
            if convert_to_file:
                messages = '基于txt文件内容进行回复：'
            else:
                raise ValueError('消息内容为空!')
        return {
            "temporary": CONFIG["API"].get("IS_TEMP_CONVERSATION", False),
            "modelName": self.model_id,
            "message": messages.strip(),
            "fileAttachments": file_attachments[:4],
            "imageAttachments": [],
            "disableSearch": False,
            "enableImageGeneration": True,
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "enableImageStreaming": False,
            "imageGenerationCount": 1,
            "forceConcise": False,
            "toolOverrides": {
                "imageGen": request["model"] in ['grok-2-imageGen', 'grok-3-imageGen'],
                "webSearch": search,
                "xSearch": search,
                "xMediaSearch": search,
                "trendsSearch": search,
                "xPostAnalyze": search
            },
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "customPersonality": "",
            "deepsearchPreset": deepsearchPreset,
            "isReasoning": request["model"] == 'grok-3-reasoning',
            "disableTextFollowUps": True
        }

class MessageProcessor:
    @staticmethod
    def create_chat_response(message, model, is_stream=False):
        base_response = {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "created": int(time.time()),
            "model": model
        }

        if is_stream:
            return {
                **base_response,
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": message
                    }
                }]
            }

        return {
            **base_response,
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": message
                },
                "finish_reason": "stop"
            }],
            "usage": None
        }

def process_model_response(response, model):
    result = {"token": None, "imageUrl": None}

    if CONFIG["IS_IMG_GEN"]:
        if response.get("cachedImageGenerationResponse") and not CONFIG["IS_IMG_GEN2"]:
            result["imageUrl"] = response["cachedImageGenerationResponse"]["imageUrl"]
        return result

    if model == 'grok-2':
        result["token"] = response.get("token")
    elif model in ['grok-2-search', 'grok-3-search']:
        if response.get("webSearchResults") and CONFIG["ISSHOW_SEARCH_RESULTS"]:
            result["token"] = f"\r\n<think>{Utils.organize_search_results(response['webSearchResults'])}</think>\r\n"
        else:
            result["token"] = response.get("token")
    elif model == 'grok-3':
        result["token"] = response.get("token")
    elif model in ['grok-3-deepsearch', 'grok-3-deepersearch']:
        if response.get("messageStepId") and not CONFIG["SHOW_THINKING"]:
            return result
        if response.get("messageStepId") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "final":
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        elif (response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "assistant") or response.get("messageTag") == "final":
            result["token"] = response.get("token","")
        elif (CONFIG["IS_THINKING"] and response.get("token","") and isinstance(response.get("token"), dict) and response.get("token").get("action","") == "webSearch"):
            result["token"] = response.get("token","").get("action_input","").get("query","")
        elif (CONFIG["IS_THINKING"] and response.get("webSearchResults")):
            result["token"] = Utils.organize_search_results(response['webSearchResults'])
    elif model == 'grok-3-reasoning':
        if response.get("isThinking") and not CONFIG["SHOW_THINKING"]:
            return result

        if response.get("isThinking") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("isThinking") and CONFIG["IS_THINKING"]:
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        else:
            result["token"] = response.get("token")

    return result

def handle_image_response(image_url):
    max_retries = 2
    retry_count = 0
    image_base64_response = None

    while retry_count < max_retries:
        try:
            proxy_options = Utils.get_proxy_options()
            image_base64_response = curl_requests.get(
                f"https://assets.grok.com/{image_url}",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie":CONFIG["SERVER"]['COOKIE'],
                    "x-statsig-id": Utils.get_statsig_id(),
                    "x-xai-request-id": str(uuid.uuid4())
                },
                impersonate="chrome133a",
                **proxy_options
            )

            if image_base64_response.status_code == 200:
                break

            retry_count += 1
            if retry_count == max_retries:
                raise Exception(f"上游服务请求失败! status: {image_base64_response.status_code}")

            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

        except Exception as error:
            logger.error(str(error), "Server")
            retry_count += 1
            if retry_count == max_retries:
                raise

            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

    image_buffer = image_base64_response.content

    if not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"]:
        base64_image = base64.b64encode(image_buffer).decode('utf-8')
        image_content_type = image_base64_response.headers.get('content-type', 'image/jpeg')
        return f"![image](data:{image_content_type};base64,{base64_image})"

    logger.info("开始上传图床", "Server")

    if CONFIG["API"]["PICGO_KEY"]:
        files = {'source': ('image.jpg', image_buffer, 'image/jpeg')}
        headers = {
            "X-API-Key": CONFIG["API"]["PICGO_KEY"]
        }
        # Using requests for PicGo as it might not need impersonation like curl_cffi
        response_url = requests.post(
            "https://www.picgo.net/api/1/upload",
            files=files,
            headers=headers
        )

        if response_url.status_code != 200:
            return "生图失败，请查看PICGO图床密钥是否设置正确"
        else:
            logger.info("生图成功", "Server")
            result = response_url.json()
            return f"![image]({result['image']['url']})"


    elif CONFIG["API"]["TUMY_KEY"]:
        files = {'file': ('image.jpg', image_buffer, 'image/jpeg')}
        headers = {
            "Accept": "application/json",
            'Authorization': f"Bearer {CONFIG['API']['TUMY_KEY']}"
        }
        # Using requests for TUMY
        response_url = requests.post(
            "https://tu.my/api/v1/upload",
            files=files,
            headers=headers
        )

        if response_url.status_code != 200:
            return "生图失败，请查看TUMY图床密钥是否设置正确"
        else:
            try:
                result = response_url.json()
                logger.info("生图成功", "Server")
                return f"![image]({result['data']['links']['url']})"
            except Exception as error:
                logger.error(str(error), "Server")
                return "生图失败，请查看TUMY图床密钥是否设置正确"
    return "图床未配置或上传失败"


def handle_non_stream_response(response, model):
    try:
        logger.info("开始处理非流式响应", "Server")

        stream = response.iter_lines()
        full_response = ""

        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False

        for chunk in stream:
            if not chunk:
                continue
            try:
                line_json = json.loads(chunk.decode("utf-8").strip())
                if line_json.get("error"):
                    logger.error(json.dumps(line_json, indent=2), "Server")
                    # Propagate a more structured error if possible
                    error_detail = line_json["error"].get("message", "RateLimitError or other upstream error")
                    return json.dumps({"error": error_detail }) + "\n\n"


                response_data = line_json.get("result", {}).get("response")
                if not response_data:
                    continue

                if response_data.get("doImgGen") or response_data.get("imageAttachmentInfo"):
                    CONFIG["IS_IMG_GEN"] = True

                result = process_model_response(response_data, model)

                if result["token"]:
                    full_response += result["token"]

                if result["imageUrl"]:
                    CONFIG["IS_IMG_GEN2"] = True
                    return handle_image_response(result["imageUrl"])

            except json.JSONDecodeError:
                logger.warning(f"无法解析JSON行: {chunk.decode('utf-8', errors='ignore')}", "Server")
                continue
            except Exception as e:
                logger.error(f"处理非流式响应行时出错: {str(e)}", "Server")
                continue # Or decide if this error should halt processing

        return full_response
    except Exception as error:
        logger.error(f"处理非流式响应时发生严重错误: {str(error)}", "Server")
        raise


def handle_stream_response(response, model):
    def generate():
        logger.info("开始处理流式响应", "Server")

        stream = response.iter_lines()
        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False

        for chunk in stream:
            if not chunk:
                continue
            try:
                line_json = json.loads(chunk.decode("utf-8").strip())
                # print(line_json) # Keep for debugging if necessary, otherwise remove for production
                if line_json.get("error"):
                    logger.error(json.dumps(line_json, indent=2), "Server")
                    error_detail = line_json["error"].get("message", "RateLimitError or other upstream error")
                    yield f"data: {json.dumps(MessageProcessor.create_chat_response(json.dumps({'error': error_detail}), model, True))}\n\n"
                    return

                response_data = line_json.get("result", {}).get("response")
                if not response_data:
                    continue

                if response_data.get("doImgGen") or response_data.get("imageAttachmentInfo"):
                    CONFIG["IS_IMG_GEN"] = True

                result = process_model_response(response_data, model)

                if result["token"]:
                    yield f"data: {json.dumps(MessageProcessor.create_chat_response(result['token'], model, True))}\n\n"

                if result["imageUrl"]:
                    CONFIG["IS_IMG_GEN2"] = True
                    image_data = handle_image_response(result["imageUrl"])
                    yield f"data: {json.dumps(MessageProcessor.create_chat_response(image_data, model, True))}\n\n"

            except json.JSONDecodeError:
                logger.warning(f"无法解析流式JSON行: {chunk.decode('utf-8', errors='ignore')}", "Server")
                continue
            except Exception as e:
                logger.error(f"处理流式响应行时出错: {str(e)}", "Server")
                # Optionally yield an error message to the client
                # yield f"data: {json.dumps(MessageProcessor.create_chat_response(json.dumps({'error': f'Stream processing error: {str(e)}'}), model, True))}\n\n"
                continue # Or decide if this error should halt generation

        yield "data: [DONE]\n\n"
    return generate()


def initialization():
    sso_array = os.environ.get("SSO", "").split(',')
    logger.info("开始加载令牌", "Server")
    token_manager.load_token_status()
    for sso in sso_array:
        if sso:
            token_manager.add_token(f"sso-rw={sso};sso={sso}",True)
    token_manager.save_token_status()

    logger.info(f"成功加载令牌: {json.dumps(token_manager.get_all_tokens(), indent=2)}", "Server")
    logger.info(f"令牌加载完成，共加载: {len(token_manager.get_all_tokens())}个令牌", "Server")

    if CONFIG["API"]["PROXY"]:
        logger.info(f"代理已设置: {CONFIG['API']['PROXY']}", "Server")

# This should be called after token_manager is instantiated
# logger.info("初始化完成", "Server") # Moved to after token_manager instantiation

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)
app.json.sort_keys = False

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if CONFIG["ADMIN"]["MANAGER_SWITCH"]:
        if request.method == 'POST':
            password = request.form.get('password')
            if password == CONFIG["ADMIN"]["PASSWORD"]:
                session['is_logged_in'] = True
                return redirect('/manager')
            return render_template('login.html', error=True)
        return render_template('login.html', error=False)
    else:
        return redirect('/')

def check_auth():
    return session.get('is_logged_in', False)

@app.route('/manager')
def manager():
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"]: # Redirect if manager is disabled
        return redirect('/')
    if not check_auth():
        return redirect('/manager/login')
    return render_template('manager.html')

@app.route('/manager/api/get')
def get_manager_tokens():
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"] or not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(token_manager.get_token_status_map())

@app.route('/manager/api/add', methods=['POST'])
def add_manager_token():
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"] or not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get('sso')
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.add_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/delete', methods=['POST'])
def delete_manager_token():
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"] or not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get('sso')
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.delete_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/cf_clearance', methods=['POST'])
def setCf_Manager_clearance():
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"] or not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        cf_clearance = request.json.get('cf_clearance')
        if not cf_clearance: # Allow empty string to clear it
             CONFIG["SERVER"]['CF_CLEARANCE'] = None
             return jsonify({"success": True, "message": "CF Clearance cleared"})
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get/tokens', methods=['GET'])
def get_tokens():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法获取轮询sso令牌状态'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    return jsonify(token_manager.get_token_status_map())

@app.route('/add/token', methods=['POST'])
def add_token():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法添加sso令牌'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401

    try:
        sso = request.json.get('sso')
        if not sso: # Basic validation
            return jsonify({"error": 'SSO token is required in JSON payload'}), 400
        token_manager.add_token(f"sso-rw={sso};sso={sso}")
        return jsonify(token_manager.get_token_status_map().get(sso, {})), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '添加sso令牌失败'}), 500

@app.route('/set/cf_clearance', methods=['POST'])
def setCf_clearance():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    try:
        cf_clearance = request.json.get('cf_clearance')
        # Allow clearing the cf_clearance by sending null or empty string
        if cf_clearance is None or cf_clearance == "":
            CONFIG["SERVER"]['CF_CLEARANCE'] = None
            logger.info("CF Clearance cleared via API.", "Server")
        else:
            CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance
            logger.info(f"CF Clearance set via API: {cf_clearance}", "Server")
        return jsonify({"message": '设置cf_clearance成功'}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '设置cf_clearance失败'}), 500

@app.route('/delete/token', methods=['POST'])
def delete_token():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法删除sso令牌'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401

    try:
        sso = request.json.get('sso')
        if not sso: # Basic validation
            return jsonify({"error": 'SSO token is required in JSON payload'}), 400
        token_manager.delete_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"message": '删除sso令牌成功'}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '删除sso令牌失败'}), 500

@app.route('/v1/models', methods=['GET'])
def get_models():
    return jsonify({
        "object": "list",
        "data": [
            {
                "id": model,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "grok"
            }
            for model in CONFIG["MODELS"].keys()
        ]
    })

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    response_status_code = 500 # Default to server error
    try:
        auth_token = request.headers.get('Authorization',
                                         '').replace('Bearer ', '')
        if auth_token:
            if CONFIG["API"]["IS_CUSTOM_SSO"]:
                result = f"sso={auth_token};sso-rw={auth_token}"
                token_manager.set_token(result)
            elif auth_token != CONFIG["API"]["API_KEY"]:
                response_status_code = 401
                return jsonify({"error": 'Unauthorized'}), response_status_code
        else:
            response_status_code = 401
            return jsonify({"error": 'API_KEY缺失'}), response_status_code

        data = request.json
        model = data.get("model")
        if not model: # Ensure model is provided
            response_status_code = 400
            return jsonify({"error": "model is a required property"}), response_status_code

        stream = data.get("stream", False)

        retry_count = 0
        grok_client = GrokApiClient(model) # This can raise ValueError if model is not supported
        request_payload = grok_client.prepare_chat_request(data) # This can raise ValueError
        logger.info(f"Request payload: {json.dumps(request_payload,indent=2)}")

        while retry_count < CONFIG["RETRY"]["MAX_ATTEMPTS"]:
            retry_count += 1
            CONFIG["API"]["SIGNATURE_COOKIE"] = Utils.create_auth_headers(model)

            if not CONFIG["API"]["SIGNATURE_COOKIE"]:
                raise ValueError('该模型无可用令牌') # This will be caught by the outer try-except

            logger.info(
                f"当前令牌: {json.dumps(CONFIG['API']['SIGNATURE_COOKIE'], indent=2)}","Server")
            logger.info(
                f"当前可用模型的全部可用数量: {json.dumps(token_manager.get_remaining_token_request_capacity(), indent=2)}","Server")

            if CONFIG['SERVER']['CF_CLEARANCE']:
                CONFIG["SERVER"]['COOKIE'] = f"{CONFIG['API']['SIGNATURE_COOKIE']};{CONFIG['SERVER']['CF_CLEARANCE']}"
            else:
                CONFIG["SERVER"]['COOKIE'] = CONFIG['API']['SIGNATURE_COOKIE']
            # logger.info(f"Request payload before send: {json.dumps(request_payload,indent=2)}","Server") # Already logged above
            logger.info(f"Using cookie: {CONFIG['SERVER']['COOKIE']}", "Server")
            try:
                proxy_options = Utils.get_proxy_options()
                response = curl_requests.post(
                    f"{CONFIG['API']['BASE_URL']}/rest/app-chat/conversations/new",
                    headers={
                        **DEFAULT_HEADERS,
                        "Cookie": CONFIG["SERVER"]['COOKIE'],
                        "x-statsig-id": Utils.get_statsig_id(),
                        "x-xai-request-id": str(uuid.uuid4())
                    },
                    data=json.dumps(request_payload),
                    impersonate="chrome133a",
                    stream=True, # Always true for iter_lines
                    timeout=60, # Add a timeout
                    **proxy_options
                )

                logger.info(f"Response status code: {response.status_code}", "Server")
                # logger.info(f"Response headers: {response.headers}", "Server") # For debugging

                if response.status_code == 200:
                    response_status_code = 200
                    logger.info("请求成功", "Server")
                    logger.info(f"当前{model}剩余可用令牌数: {token_manager.get_token_count_for_model(model)}","Server")

                    try:
                        if stream:
                            return Response(stream_with_context(
                                handle_stream_response(response, model)),content_type='text/event-stream')
                        else:
                            content = handle_non_stream_response(response, model)
                            # Check if content itself is an error JSON string
                            try:
                                error_check = json.loads(content)
                                if isinstance(error_check, dict) and "error" in error_check:
                                    logger.error(f"Non-stream response indicates error: {content}", "Server")
                                    # Determine appropriate status code, perhaps 4xx or 5xx from upstream if available
                                    # For now, returning 500 if it's an error string from our handler.
                                    response_status_code = 503 # Service Unavailable from upstream
                                    return jsonify({"error": {"message": error_check["error"], "type": "upstream_error"}}), response_status_code
                            except json.JSONDecodeError:
                                pass # It's a normal content string

                            return jsonify(
                                MessageProcessor.create_chat_response(content, model))

                    except Exception as error: # Errors during stream/non-stream processing
                        logger.error(f"Error processing upstream response: {str(error)}", "Server")
                        if CONFIG["API"]["IS_CUSTOM_SSO"]:
                            # For custom SSO, let the main exception handler deal with it.
                             raise ValueError(f"自定义SSO令牌当前模型{model}的请求处理失败: {str(error)}")

                        token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])
                        if token_manager.get_token_count_for_model(model) == 0:
                             raise ValueError(f"{model} 次数已达上限或令牌失效，请切换其他模型或者重新对话")
                        # If there are still tokens, this specific attempt failed, loop will continue if MAX_ATTEMPTS not reached
                        # If we reach here, it means retry might be needed.
                        if retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                            raise ValueError(f"处理响应失败，已达最大重试次数: {str(error)}")
                        continue # Continue to next retry attempt

                elif response.status_code == 403:
                    response_status_code = 403
                    logger.warning(f"请求被拒绝 (403 Forbidden). IP可能被封锁. Response: {response.text}", "Server")
                    token_manager.reduce_token_request_count(model,1) # Reset count for this failed attempt
                    # No need to remove token unless it's specifically a token issue
                    raise ValueError(f"IP暂时被封无法破盾 (403 Forbidden)，请稍后重试或者更换ip")
                elif response.status_code == 429:
                    response_status_code = 429
                    logger.warning(f"请求速率过快 (429 Too Many Requests). Response: {response.text}", "Server")
                    token_manager.reduce_token_request_count(model,1)
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                        raise ValueError(f"自定义SSO令牌当前模型{model}的请求次数已失效 (429)")

                    token_manager.remove_token_from_model(
                        model, CONFIG["API"]["SIGNATURE_COOKIE"])
                    logger.info(f"因429错误移除令牌: {CONFIG['API']['SIGNATURE_COOKIE']} for model {model}", "Server")
                    if token_manager.get_token_count_for_model(model) == 0:
                        raise ValueError(f"{model} 次数已达上限，请切换其他模型或者重新对话 (429)")
                    # Loop will continue if MAX_ATTEMPTS not reached and other tokens are available

                else: # Other non-200 status codes
                    response_status_code = response.status_code
                    logger.error(f"上游API请求失败，状态码: {response.status_code}. Response: {response.text}", "Server")
                    token_manager.reduce_token_request_count(model,1) # Reduce count for this failed attempt
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                         raise ValueError(f"自定义SSO令牌请求失败，状态码: {response.status_code}")

                    # Consider removing token for persistent errors other than 429, e.g., 401, 400 on token
                    if response.status_code in [400, 401]: # Example: Bad request or Unauthorized likely token related
                        logger.info(f"因 {response.status_code} 错误移除令牌: {CONFIG['API']['SIGNATURE_COOKIE']} for model {model}", "Server")
                        token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])

                    if token_manager.get_token_count_for_model(model) == 0:
                        raise ValueError(f"{model} 所有令牌均已尝试或失效，状态码: {response.status_code}")
                    # Loop will continue for retry if applicable

            except (curl_requests.RequestsError, requests.exceptions.RequestException) as e: # Network or curl_cffi specific errors
                logger.error(f"请求处理时发生网络或连接错误: {str(e)}", "Server")
                # Decrement count as the request didn't effectively use the token's quota with the upstream
                token_manager.reduce_token_request_count(model, 1)
                if CONFIG["API"]["IS_CUSTOM_SSO"]:
                    raise # Let the main handler catch this for custom SSO
                if retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                    response_status_code = 503 # Service unavailable after retries
                    raise ValueError(f"网络或连接错误，已达最大重试次数: {str(e)}")
                time.sleep(1) # Wait a bit before retrying on network issues
                continue # Continue to next retry attempt
            # If we successfully got a response (even an error one) and it's not a retryable case handled above, break from while.
            # This break is important to prevent infinite loops if a non-200 code isn't explicitly handled for retry.
            # However, the current logic has specific error handling that either raises (to be caught by outer) or continues the loop.
            # If a 200 response was processed (stream or non-stream), the function would have returned already.
            # If it was a handled error (403, 429, etc.) it either raises or continues based on token availability.
            # So, if we are still in the loop here after an attempt, it means a retry is intended by `continue` or an unhandled status code occurred.
            if response.status_code != 200: # If not 200 and not explicitly continued for retry
                if retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                    raise ValueError(f"上游API请求失败，状态码: {response.status_code}，已达最大重试次数")
                # else continue to retry
            else: # successful 200, should have returned
                break


        # If loop finishes without returning/raising, it means all retries failed for some reason
        # This part should ideally not be reached if all paths are handled (return on success, raise on terminal failure, continue on retry)
        if response_status_code != 200: # Check the last status code if loop exhausted
             raise ValueError(f'当前模型所有令牌暂无可用或请求失败，最后状态码: {response_status_code}')


    except ValueError as ve: # Catch specific ValueErrors for clearer client messages
        logger.error(f"参数或配置错误: {str(ve)}", "ChatAPI")
        # Determine status code based on error type if possible
        if "API_KEY缺失" in str(ve) or "Unauthorized" in str(ve):
            response_status_code = 401
        elif "model is a required property" in str(ve) or "不支持的模型" in str(ve) or "消息内容为空!" in str(ve):
            response_status_code = 400
        elif "该模型无可用令牌" in str(ve) or "次数已达上限" in str(ve) or "所有令牌均已尝试或失效" in str(ve):
            response_status_code = 503 # Service Unavailable (no tokens)
        # else keep default 500 or last known if set
        if response_status_code == 500 and ("IP暂时被封" in str(ve) or "403" in str(ve)): # Check specific error messages
            response_status_code = 403

        return jsonify(
            {"error": {
                "message": str(ve),
                "type": "invalid_request_error" if response_status_code == 400 or response_status_code == 401 else "server_error"
            }}), response_status_code
    except Exception as error: # Catch-all for other unexpected errors
        logger.error(f"发生意外错误: {str(error)}", "ChatAPI")
        return jsonify(
            {"error": {
                "message": f"An unexpected error occurred: {str(error)}",
                "type": "server_error"
            }}), 500 # Always 500 for truly unexpected

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if path == "favicon.ico":
        return "", 204 # No content for favicon
    return 'API 运行正常 (grok2api-reverse)', 200

if __name__ == '__main__':
    token_manager = AuthTokenManager()
    initialization() # Initialize after token_manager is created
    logger.info("应用初始化完成", "Server") # Log after all setup

    app.run(
        host='0.0.0.0',
        port=CONFIG["SERVER"]["PORT"],
        debug=False # Should be False for production
    )
