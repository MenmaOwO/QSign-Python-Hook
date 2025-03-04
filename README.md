

以下是为该项目编写的详细 `README.md`，包含使用指南、风险提示、调用示例等关键信息：

---

# QQ 安全签名服务 (QSign Server)

基于 Frida 的 QQ 安全签名服务，提供 HTTP 接口与安卓客户端交互，支持签名生成、日志追踪和实时统计。

---

## 目录
- [功能特性](#功能特性)
- [环境准备](#环境准备)
- [快速开始](#快速开始)
- [API 文档](#api-文档)
- [风险须知](#风险须知)
- [调用示例](#调用示例)
- [返回数据示例](#返回数据示例)
- [日志与统计](#日志与统计)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

---

## 功能特性
✅ **核心功能**  
- 通过 USB 调试与安卓设备通信
- 支持 `com.tencent.mobileqq:MSF` 包名
- 参数严格校验（十六进制、序列号格式）
- 实时统计面板与日志查询
- 多线程任务队列（最大 10 并发）

✅ **监控能力**  
- 请求耗时统计
- 成功率分析
- UIN 调用排名
- 小时级请求分布

---

## 环境准备
### 1. 依赖安装
```bash
pip install -r requirements.txt
```
**必需组件**：  
- Python 3.8+  
- Frida 16.0+  
- Android 设备（启用 USB 调试）

### 2. 配置文件
创建 `config.py`：
```python
# config.py
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
```

---

## 快速开始
### 启动服务
```bash
python app.py
# 默认监听 0.0.0.0:5000
```


---

## API 文档
### `POST/GET /sign`
#### 请求参数
| 参数       | 类型   | 必填 | 说明                          |
|------------|--------|------|-------------------------------|
| cmd        | string | 是   | 命令类型（如 `wtlogin.login`） |
| seq        | string | 是   | 请求序列号（数字字符串）       |
| buffer     | string | 是   | 十六进制数据                  |
| uin        | string | 是   | 用户唯一标识                  |
| qua        | string | 是   | 客户端标识                    |
| package    | string | 是   | 目标包名（必须为 `com.tencent.mobileqq:MSF`） |

#### 错误码
| 状态码 | 说明                 |
|--------|----------------------|
| 400    | 参数缺失/格式错误     |
| 500    | 服务端异常或签名失败 |

---

## 风险须知
⚠️ **重要提示**  
1. 本工具依赖 USB 调试模式，仅限在**授权设备**上使用。
2. 可能触发设备安全机制，请确保已获得合法授权。
3. 不记录敏感数据，但建议在安全网络环境下使用。
4. 禁止用于非法逆向工程或数据窃取。

---

## 调用示例
### POST 请求
```bash
curl -X POST http://localhost:5000/sign \
-H "Content-Type: application/json" \
-d '{
    "cmd": "wtlogin.login",
    "seq": "123456",
    "buffer": "00010203040506070809",
    "uin": "10001",
    "qua": "V1_AND_SQ_8.9.53_3362_YYB_D",
    "package": "com.tencent.mobileqq:MSF"
}'
```

### GET 请求
```bash
curl "http://localhost:5000/sign?cmd=wtlogin.login&seq=123456&buffer=00010203040506070809&uin=10001&qua=V1_AND_SQ_8.9.53_3362_YYB_D&package=com.tencent.mobileqq:MSF"
```

---

## 返回数据示例
### 成功响应
```json
{
    "data": {
        "extra": "1201311a9001413332453339333930354638343030303336314231313734313241444434424131313132393743353637463332304545333846443235384635304632313030443831353932443635344534393539444241443143333432393731393232333635374244353246444334374533373145433235434645343742443939453936304544334531414144413233453833463443",
        "sign": "0c214a9dfbedbf45c59972071f8a77aed1d19971ffde7175eeba299a74a9fff3d5a616a3e530c068201829e9f4ec25c9dbfebf347e03ef96093c664472d38b7837f0cc8b80f3738b75953720",
        "token": "4344792f512b497a65335447"
    },
    "status": "success"
}
```

### 错误响应
```json
{
  "status": "error",
  "message": "参数格式错误: buffer 应为十六进制"
}
```

---

## 日志与统计
### 实时统计面板
访问 `http://localhost:5000/stats` 查看：  
- 总请求量
- 成功率曲线
- 响应时间分布
- 热点 UIN 排行

### 日志查询
访问 `http://localhost:5000/logs` 查看原始日志（支持分页）。


---

## 许可证
本项目采用 [MIT License](LICENSE)，详细条款见 LICENSE 文件。

---

