# APISentinel_Bluechips

> 专为渗透测试人员打造的 API 接口自动化安全检测工具  
> Author: bluechips | Version: 1.0.0

---

## 目录

- [简介](#简介)
- [功能特性](#功能特性)
- [安装与配置](#安装与配置)
- [快速入门](#快速入门)
- [主界面功能](#主界面功能)
- [设置面板](#设置面板)
- [高级功能](#高级功能)
- [常见问题](#常见问题)
- [项目结构](#项目结构)

---

## 简介

APISentinel_Bluechips 是一款专为渗透测试人员打造的 API 接口自动化安全检测工具。它能够自动解析 Swagger/OpenAPI 和 ASP.NET Help Page 文档，智能填充参数，批量测试接口，并提供强大的敏感信息检测和漏洞扫描功能。

---

## 功能特性

| 功能 | 描述 |
|------|------|
| 📄 **多文档格式支持** | Swagger 2.0/3.0、ASP.NET Help Page |
| 🔍 **智能参数填充** | 自动识别参数类型并生成测试数据 |
| 🎯 **多格式测试** | URL 参数、JSON Body、Form Body 三种格式 |
| 🔐 **敏感信息检测** | 100+ 内置规则，覆盖云服务密钥、Token、个人信息等 |
| 🛡️ **IDOR 检测** | 自动检测不安全的直接对象引用漏洞 |
| 🔑 **认证绕过测试** | Token 绕过、HTTP 方法绕过、请求头绕过 |
| 📡 **JWT 安全检测** | 弱密钥检测、alg:none 漏洞、算法混淆攻击 |
| 🚀 **批量测试** | 并发执行，提高效率 |
| 📊 **结果去重** | 智能过滤重复响应 |
| 📈 **多格式导出** | Excel、CSV、JSON、HTML |

---

## 安装与配置

### 系统要求

- **操作系统**：Windows 10/11
- **Python 版本**：Python 3.8 或更高版本
- **内存**：至少 4GB RAM

### 安装步骤

```bash
# 1. 进入项目目录
cd APISentinel_Bluechips

# 2. 安装依赖
pip install -r requirements.txt

# 3. 运行程序
python src/main.py
```

---

## 快速入门

### 第一步：启动程序

```bash
python src/main.py
```

### 第二步：导入 API 文档

1. 选择文档类型：
   - **Swagger/OpenAPI**：输入 JSON URL 或选择本地文件
   - **ASP.NET Help Page**：输入帮助页面 URL

2. 示例 URL：
   ```
   Swagger: https://petstore.swagger.io/v2/swagger.json
   ASP.NET: http://example.com/Help
   ```

3. 点击"导入"按钮

### 第三步：选择接口

在接口列表中勾选要测试的接口

### 第四步：开始测试

点击工具栏的"开始测试"按钮

### 第五步：查看结果

- 在测试结果区域查看详细信息
- 双击结果查看完整请求和响应
- 点击"导出结果"保存到 Excel

---

## 主界面功能

### 工具栏按钮

| 按钮 | 颜色 | 功能 |
|------|------|------|
| ▶ 开始测试 | 🟢 绿色 | 开始执行选中的接口测试 |
| ⏹ 停止测试 | 🔴 红色 | 停止正在进行的测试 |
| 🗑 清空结果 | 🟠 橙色 | 清空测试结果列表 |
| 📊 导出结果 | 🔵 蓝色 | 导出结果到 Excel 文件 |
| ⚙ 设置 | 🟣 紫色 | 打开设置对话框 |

### 接口列表

| 列名 | 说明 |
|------|------|
| 选择 | 勾选要测试的接口 |
| 方法 | HTTP 方法（GET、POST、PUT、DELETE 等） |
| URL | 接口的完整 URL |
| 描述 | 接口的功能描述 |
| 标签 | 接口的分类标签 |
| 状态 | 接口状态（就绪、测试中、已完成） |

### 结果列表

| 列名 | 说明 |
|------|------|
| ID | 结果序号 |
| 方法 | HTTP 方法 |
| URL | 请求的 URL |
| 状态码 | HTTP 响应状态码 |
| 长度 | 响应体长度（字节） |
| 时间 | 响应时间（秒） |
| 敏感信息 | 检测到的敏感信息数量 |
| 操作 | 查看详情按钮 |

---

## 设置面板

### 1. 敏感规则标签页

管理敏感信息检测规则，支持添加、编辑、删除、导入、导出规则。

**内置规则分类：**

- **云服务密钥**：AWS、阿里云、腾讯云、Google Cloud、Azure
- **Token**：JWT、GitHub、Slack、Stripe、PayPal
- **数据库连接串**：MySQL、PostgreSQL、MongoDB、Redis
- **个人隐私信息**：手机号、身份证号、邮箱、银行卡号

### 2. 请求头标签页

配置自定义请求头，用于认证、绕过限制等场景。

**快捷添加：**
- Cookie
- Authorization
- User-Agent

### 3. 变异测试标签页

配置 Fuzzing Payload，用于参数变异测试。

**Payload 分类：**
- SQL 注入
- XSS 攻击
- 路径遍历
- 命令注入
- 自定义

### 4. 安全设置标签页

配置安全模式，防止在测试过程中误删数据。

**安全模式功能：**
- 拦截 DELETE 方法
- 拦截 PUT 方法
- 跳过包含危险关键词的接口
- 应用 URL 黑名单

---

## 高级功能

### IDOR 自动检测

自动检测不安全的直接对象引用漏洞：
1. 识别 ID 类参数（user_id、order_id、account_id 等）
2. 生成 ID 变异值（+1、-1、+10、-10、0、-1）
3. 发送修改后的请求
4. 对比响应差异判断漏洞

### 认证绕过测试

测试多种认证绕过方式：
- **Token 绕过**：空 Token、过期 Token、无效 Token
- **HTTP 方法绕过**：GET↔POST 转换、X-HTTP-Method-Override
- **请求头绕过**：X-Forwarded-For、X-Original-URL、X-Real-IP 等

### JWT 安全检测

全面的 JWT 安全检测：
- JWT Token 识别和解析
- 弱密钥检测（内置 60+ 常见弱密钥）
- alg:none 漏洞测试
- 算法混淆攻击（RS256→HS256）
- Payload 敏感信息检测

### 上传漏洞检测

自动检测文件上传漏洞：
- 自动识别上传接口
- 测试多种上传场景（XSS、双扩展名、空字节注入等）
- 检测危险文件上传
- 验证上传文件可访问性

### 请求链执行

支持复杂的 API 测试场景：
- 按顺序执行多个 API 请求
- 步骤间变量传递和提取
- 支持从 Header、Body、Cookie 提取数据
- 支持正则表达式和 JSONPath 提取

### 结果导出

支持格式：Excel (.xlsx)、CSV (.csv)、JSON (.json)、HTML (.html)

---

## 常见问题

### Q1: 如何配置代理？

在测试结果面板的代理输入框中输入：
```
http://127.0.0.1:8080
```

### Q2: 如何测试需要认证的接口？

在设置面板的"请求头"标签页中添加：
```
Authorization: Bearer your_token_here
```

### Q3: 如何避免误删生产数据？

启用安全模式：
1. 打开设置面板
2. 切换到"安全设置"标签页
3. 勾选"启用安全模式（默认开启）"
4. 选择要拦截的 HTTP 方法（DELETE、PUT、PATCH）

### Q4: 导入 Swagger 文档失败？

检查：
1. URL 是否可访问
2. 是否为有效的 JSON 格式
3. 是否为 Swagger 2.0 或 OpenAPI 3.0 格式

### Q5: 如何查看敏感信息检测结果？

在测试结果列表中：
1. 查看"敏感信息"列的数量
2. 双击结果行查看详细信息
3. 在详情对话框中查看检测到的敏感信息列表

### Q6: 如何使用 JWT 检测功能？

JWT 检测功能已自动集成：
- 在测试过程中自动识别 JWT Token
- 自动解析 JWT 的 Header、Payload、Signature
- 自动检测弱密钥和常见漏洞
- 在测试结果中查看 JWT 分析报告

### Q7: 如何启用高级检测功能？

高级检测功能（IDOR、认证绕过、上传漏洞）默认禁用，需要在代码中手动启用：
```python
from src.engines import TestExecutor

executor = TestExecutor(
    enable_sensitive_detection=True,           # 敏感信息检测（默认启用）
    enable_jwt_detection=True,                 # JWT 检测（默认启用）
    enable_idor_detection=True,                # IDOR 检测（可选）
    enable_auth_bypass_detection=True,         # 认证绕过检测（可选）
    enable_upload_detection=True               # 上传漏洞检测（可选）
)
```

---

## 项目结构

```
APISentinel_Bluechips/
├── src/
│   ├── main.py              # 程序入口
│   ├── core/
│   │   ├── models.py        # 数据模型
│   │   └── http_client.py   # HTTP 客户端
│   ├── parsers/
│   │   ├── swagger_parser.py    # Swagger 解析器
│   │   └── aspnet_parser.py     # ASP.NET 解析器
│   ├── engines/
│   │   ├── param_filler.py      # 参数填充
│   │   ├── request_builder.py   # 请求构建
│   │   ├── test_executor.py     # 测试执行
│   │   ├── sensitive_detector.py # 敏感信息检测
│   │   ├── idor_detector.py     # IDOR 检测
│   │   ├── auth_bypass.py       # 认证绕过
│   │   ├── jwt_detector.py      # JWT 检测
│   │   ├── deduplicator.py      # 结果去重
│   │   ├── exporter.py          # 结果导出
│   │   └── safe_mode.py         # 安全模式
│   └── ui/
│       ├── main_window.py       # 主窗口
│       └── settings_dialog.py   # 设置对话框
├── config/
│   └── settings.json        # 配置文件
├── resources/
│   └── icon.ico             # 应用图标
├── requirements.txt         # 依赖列表
└── README.md                # 说明文档
```

---

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| Ctrl+Enter | 开始测试 |
| Ctrl+Break | 停止测试 |
| Ctrl+Delete | 清空结果 |
| Ctrl+S | 导出结果 |
| Ctrl+, | 打开设置 |

---

## ⚠️ 免责声明

本工具仅供 **授权安全测试** 与 **学术研究** 使用。

在使用本工具进行检测时，您必须确保已获得目标系统的合法授权。

**严禁使用本工具进行任何非法入侵、攻击或破坏活动。**

作者不对任何因使用本工具而导致的法律后果或连带责任承担责任。

---

## 许可证

MIT License

---

**Made with ❤️ by bluechips**
