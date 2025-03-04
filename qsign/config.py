import os

# 模板配置
TEMPLATES_AUTO_RELOAD = True  # 开发环境热重载（生产环境应设为 False）
EXPLAIN_TEMPLATE_LOADING = False  # 禁用模板加载调试信息

# 压缩配置（需配合 Flask-Compress 扩展）
COMPRESS_MIMETYPES = [
    'text/html',
    'text/css',
    'application/javascript',
    'application/json',
    'image/svg+xml'  # 增加对 SVG 的压缩支持
]
COMPRESS_LEVEL = 6  # Gzip 压缩级别（1-9，6 是平衡值）
COMPRESS_MIN_SIZE = 500  # 仅压缩大于 500 字节的响应

# 静态文件版本控制
STATIC_VERSION = '1.0.1'  # 

# API 参数定义（供模板使用）
PARAMS_DEFINITIONS = {
    "cmd": "命令字符串（示例：wtlogin.login）",
    "seq": "请求序列号（十进制字符串）",
    "buffer": "十六进制编码的二进制数据",
    "uin": "用户唯一标识（QQ号）",
    "qua": "客户端标识（示例：V1_AND_SQ_8.9.53_3362_YYB_D）",
    "package": "目标包名（必须为 com.tencent.mobileqq:MSF）"
}