# app.py
import frida
import sys
import json
import datetime
import threading
import re
import uuid
import traceback
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from flask import Flask, render_template, send_from_directory, request, jsonify
from pythonjsonlogger import jsonlogger
from flask_compress import Compress

# =================== 初始化配置 ====================
app = Flask(__name__)
app.config.from_pyfile('config.py')
app.static_folder = 'static'
executor = ThreadPoolExecutor(max_workers=10)
sessions = {}
uin_counter = defaultdict(int)
counter_lock = threading.Lock()
hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
seq_pattern = re.compile(r'^\d+$')  # 新增正则表达式用于验证 seq 参数
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "qsign.log")  # 使用绝对路径
# 启用压缩
Compress(app)

# ==================== 日志配置 ====================
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 确保日志目录存在
os.makedirs(BASE_DIR, exist_ok=True)

# 文件日志配置
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8', mode='a', delay=False)
file_formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s',
    json_ensure_ascii=False
)
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# 控制台日志配置
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# ==================== Frida 脚本 ====================
JS_CODE = """
Java.perform(function () {
    var QQSecuritySign = Java.use('com.tencent.mobileqq.sign.QQSecuritySign');
    var QSec = Java.use('com.tencent.mobileqq.qsec.qsecurity.QSec');

    function hexToBytes(hex) {
        var bytes = [];
        for (var i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return bytes;
    }

    function bytesToHex(bytes) {
        return Array.from(bytes).map(function (byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    }

    rpc.exports = {
        triggerGetSign: function (params) {
            try {
                var qua = params.qua; 
                var cmd = params.cmd;
                var buffer = Java.array('byte', hexToBytes(params.buffer));
                var seq = Java.array('byte', hexToBytes(params.seq));
                var uin = params.uin;

                var qSecInstance = QSec.$new();
                qSecInstance = Java.cast(qSecInstance, QSec);
                
                var instance = QQSecuritySign.getInstance();
                var signResult = instance.getSign(qSecInstance, qua, cmd, buffer, seq, uin);

                return {
                    extra: bytesToHex(signResult.extra.value),
                    sign: bytesToHex(signResult.sign.value),
                    token: bytesToHex(signResult.token.value)
                };
            } catch (e) {
                return {error: e.message + "\\nStack: " + e.stack};
            }
        }
    };
});
"""

# ==================== 工具函数 ==================
def is_valid_hex(s):
    return len(s) % 2 == 0 and hex_pattern.match(s) is not None

def is_valid_seq(s):
    return seq_pattern.match(s) is not None  # 新增函数用于验证 seq 参数

def attach_to_packages():
    try:
        device = frida.get_usb_device()
        target_packages = [
            "com.tencent.mobileqq:MSF"
        ]
        
        current_processes = device.enumerate_processes()
        active_packages = {p.name for p in current_processes}
        
        # 清理无效会话
        for package in list(sessions.keys()):
            if package not in active_packages:
                sessions[package]["session"].detach()
                del sessions[package]
        
        # 附加新进程
        for package in target_packages:
            if package in active_packages and package not in sessions:
                try:
                    proc = next(p for p in current_processes if p.name == package)
                    session = device.attach(proc.pid)
                    script = session.create_script(JS_CODE)
                    script.load()
                    sessions[package] = {"session": session, "script": script}
                    logger.info(f"Attached to {package}")
                except Exception as e:
                    logger.error(f"Attach failed {package}: {str(e)}")
    except Exception as e:
        logger.error(f"Attach error: {str(e)}")

# ==================== 后台线程 ====================
def auto_reattach():
    while True:
        attach_to_packages()
        threading.Event().wait(30)

# ==================== Flask 路由 ==================
@app.route('/sign', methods=['GET', 'POST'])  # 修改方法为支持GET和POST
def handle_getsign():
    start_time = datetime.datetime.now()
    log_entry = {
        "request_id": uuid.uuid4().hex,
        "client_ip": request.remote_addr,
        "start_time": start_time.isoformat(),
        "status": "processing",
        "status_code": 500,
        "params": None,
        "error": None,
        "duration_ms": 0,
        "_schema_version": "1.1"
    }
    try:
        # 根据请求方法获取参数
        if request.method == 'POST':
            data = request.get_json(force=True, silent=True) or {}
        else:  # GET请求
            data = request.args.to_dict()
        
        log_entry["params"] = data

        # 参数验证
        required_fields = ['cmd', 'seq', 'buffer', 'uin', 'qua', 'package']
        if missing := [f for f in required_fields if f not in data]:
            raise ValueError(f"缺少必填字段: {missing}")
        
        if not is_valid_hex(data.get('buffer', '')):
            raise ValueError("参数格式错误: buffer 应为十六进制")
        
        if not is_valid_seq(data.get('seq', '')):
            raise ValueError("参数格式错误: seq 应为序列数")

        # 统计计数
        with counter_lock:
            uin_counter[data['uin']] += 1
            log_entry["uin_count"] = uin_counter[data['uin']]

        # 获取脚本
        package = data["package"]
        if package not in sessions:
            raise ValueError(f"服务未就绪: {package}")
        
        script = sessions[package]["script"]
        
        # 调用Frida
        future = executor.submit(script.exports_sync.trigger_get_sign, data)
        result = future.result(timeout=10)

        if 'error' in result:
            raise RuntimeError(result["error"])
        
        response = {"status": "success", "data": result}
        log_entry["status"] = "success"
        log_entry["status_code"] = 200

    except Exception as e:
        log_entry.update({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })
        response = {"status": "error", "message": str(e)}
        log_entry["status_code"] = 400 if "缺少 " in str(e) else 500
    finally:
        duration = datetime.datetime.now() - start_time
        log_entry["duration_ms"] = round(duration.total_seconds() * 1000, 2)
        
        # 双重写入确保日志记录
        try:
            logger.info(json.dumps(log_entry, ensure_ascii=False))
            # 直接写入文件作为备份
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        except Exception as e:
            print(f"严重错误：无法写入日志文件 - {str(e)}")

    return jsonify(response), log_entry["status_code"]

# ==================== 统计函数 ====================
def generate_statistics():
    stats = {
        "total_requests": 0,
        "success_rate": 0.0,
        "error_distribution": defaultdict(int),
        "top_uin": [],
        "hourly_requests": defaultdict(int),
        "avg_duration": 0.0,
        "package_usage": defaultdict(int),
        "status_codes": defaultdict(int)
    }

    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
            total_duration = 0.0
            uin_counter = defaultdict(int)
            
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    entry = json.loads(line)
                    stats["total_requests"] += 1
                    
                    # 统计状态码
                    stats["status_codes"][entry.get("status_code", 0)] += 1
                    
                    # 统计成功率
                    if entry.get("status") == "success":
                        stats["success_rate"] += 1
                    
                    # 错误类型分布
                    if entry.get("error"):
                        error_key = entry["error"].split(":")[0].strip()
                        stats["error_distribution"][error_key] += 1
                    
                    # UIN统计
                    if params := entry.get("params"):
                        uin = params.get("uin")
                        if uin:
                            uin_counter[uin] += 1
                    
                    # 耗时统计 
                    total_duration += entry.get("duration_ms", 0)
                    
                    # 时间分布统计
                    if timestamp := entry.get("start_time"):
                        try:
                            dt = datetime.datetime.fromisoformat(timestamp)
                            hour_key = dt.strftime("%Y-%m-%d %H:00")
                            stats["hourly_requests"][hour_key] += 1
                        except ValueError:
                            pass
                    
                    # 包名使用统计
                    if params := entry.get("params"):
                        package = params.get("package")
                        if package:
                            stats["package_usage"][package] += 1

                except json.JSONDecodeError:
                    logger.error(f"无法解析日志行: {line}")
                    continue  # 忽略无法解析的行

            # 计算衍生指标
            if stats["total_requests"] > 0:
                stats["success_rate"] = round(stats["success_rate"] / stats["total_requests"] * 100, 2)
                stats["avg_duration"] = round(total_duration / stats["total_requests"], 2)
                
                # 获取TOP5 UIN
                stats["top_uin"] = sorted(
                    uin_counter.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]

            return stats

    except Exception as e:
        logger.error(f"生成统计信息失败: {str(e)}")
        return {
            "error": f"统计信息生成失败: {str(e)}",
            "total_requests": 0
        }

# ==================== 日志查看界面 ====================
@app.route('/stats')
def view_stats():
    stats = generate_statistics()
    return render_template('stats.html', stats=stats)

@app.route('/guide')
def view_guide():
    PARAMS_DEFINITIONS = {
        "cmd": "命令字符串",
        "seq": "序列号",
        "buffer": "缓冲区数据",
        "uin": "用户标识",
        "qua": "客户端标识",
        "package": "com.tencent.mobileqq:MSF"
    }
    return render_template('guide.html', params=PARAMS_DEFINITIONS)

@app.route('/logs')
def view_logs():
    # 读取并处理日志文件
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except IOError as e:
        logger.error(f"读取日志文件失败: {e}")
        return render_template('error.html', message="无法读取日志文件"), 500

    # 解析日志条目
    processed_logs = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            log_entry = json.loads(line)
            processed_logs.append(log_entry)
        except json.JSONDecodeError:
            logger.error(f"无法解析日志行: {line}")
            continue  # 忽略无法解析的行

    # 反转日志顺序（最新在前）
    processed_logs.reverse()

    # 分页处理
    page = request.args.get('page', 1, type=int)
    per_page = 20  # 每页显示数量
    total_logs = len(processed_logs)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page

    # 截取当前页数据
    paginated_logs = processed_logs[start_idx:end_idx]
    has_next = end_idx < total_logs
    has_prev = start_idx > 0

    return render_template('logs.html',
                         logs=paginated_logs,
                         page=page,
                         per_page=per_page,
                         total_logs=total_logs,
                         has_next=has_next,
                         has_prev=has_prev)

# ==================== 在应用初始化时注册模板过滤器 ====================
@app.template_filter('datetime')
def format_datetime(value):
    if not isinstance(value, str):
        return "N/A"
    try:
        # 处理可能的时间格式
        if 'T' in value:
            return datetime.datetime.fromisoformat(value).strftime('%Y-%m-%d %H:%M:%S')
        elif '.' in value:
            return datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").strftime('%Y-%m-%d %H:%M:%S')
        else:
            return datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return "Invalid Date"

@app.template_filter('tojson')
def tojson_filter(value):
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except:
        return "{}"

# ==================== 启动检查 ====================
def startup_check():
    # 检查文件权限
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n=== 服务启动 {datetime.datetime.now().isoformat()} ===\n")
        print("[启动检查] 日志文件写入测试成功")
    except PermissionError:
        print(f"[严重错误] 没有 {LOG_FILE} 文件的写入权限")
        sys.exit(1)
    except Exception as e:
        print(f"[启动错误] 文件访问异常: {str(e)}")
        sys.exit(1)

    # 检查Frida连接
    try:
        device = frida.get_usb_device()
        print(f"[启动检查] 找到USB设备: {device.name}")
    except Exception as e:
        print(f"[启动警告] Frida设备连接异常: {str(e)}")

# ==================== 主程序入口 ====================
if __name__ == "__main__":
    
    attach_to_packages()
    threading.Thread(target=auto_reattach, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, threaded=True)