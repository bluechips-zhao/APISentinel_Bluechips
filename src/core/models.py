"""
核心数据模型定义

本模块定义了 API 安全扫描工具所需的所有核心数据模型。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from datetime import datetime


@dataclass
class Parameter:
    """
    参数数据模型
    
    用于表示 API 接口的参数信息，包括查询参数、请求体参数、路径参数和请求头参数。
    
    Attributes:
        name: 参数名称
        param_type: 参数类型（query/body/path/header）
        data_type: 数据类型（string/integer/boolean等）
        required: 是否必需
        default_value: 默认值
        description: 参数描述
        example: 示例值
    """
    name: str
    param_type: str
    data_type: str
    required: bool = False
    default_value: Any = None
    description: str = ""
    example: Any = None


@dataclass
class APIEndpoint:
    """
    API 接口数据模型
    
    用于表示一个完整的 API 接口信息，包括 URL、HTTP 方法、参数、请求头等。
    
    Attributes:
        url: 接口完整 URL
        method: HTTP 方法（GET/POST/PUT/DELETE）
        path: 接口路径
        parameters: 参数列表
        headers: 请求头字典
        description: 接口描述
        tags: 标签列表
    """
    url: str
    method: str
    path: str
    parameters: List[Parameter] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class SensitiveInfo:
    """
    敏感信息数据模型
    
    用于表示在响应中检测到的敏感信息，包括规则名称、敏感等级、匹配内容等。
    
    Attributes:
        rule_name: 规则名称
        rule_level: 敏感等级（High/Medium/Low）
        pattern: 匹配的正则表达式
        matched_content: 匹配的内容
        position: 在响应中的位置（起始索引，结束索引）
    """
    rule_name: str
    rule_level: str
    pattern: str
    matched_content: str
    position: Tuple[int, int]


@dataclass
class TestResult:
    """
    测试结果数据模型
    
    用于记录一次 API 测试的完整结果，包括请求信息、响应信息和检测到的敏感信息。
    
    Attributes:
        request_id: 请求唯一标识符
        endpoint: 接口信息
        request_headers: 请求头字典
        request_body: 请求体内容
        response_status: 响应状态码
        response_headers: 响应头字典
        response_body: 响应体内容
        response_length: 响应长度（字节）
        response_time: 响应时间（秒）
        sensitive_info: 敏感信息列表
        jwt_info: JWT 检测结果列表
        idor_info: IDOR 检测结果
        auth_bypass_info: 认证绕过检测结果列表
        upload_info: 上传漏洞检测结果列表
        timestamp: 时间戳
        error: 错误信息（如果有）
    """
    request_id: str
    endpoint: APIEndpoint
    request_headers: Dict[str, str]
    request_body: str
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    response_length: int
    response_time: float
    sensitive_info: List[SensitiveInfo] = field(default_factory=list)
    jwt_info: List[Dict] = field(default_factory=list)
    idor_info: Dict = field(default_factory=dict)
    auth_bypass_info: List[Dict] = field(default_factory=list)
    upload_info: List[Dict] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    error: str = ""


@dataclass
class Config:
    """
    配置数据模型
    
    用于存储扫描工具的全局配置信息，包括代理、自定义请求头、安全模式等。
    
    Attributes:
        proxy: 代理地址
        custom_headers: 自定义请求头字典
        custom_params: 自定义参数值字典
        safe_mode: 安全模式开关（启用后将跳过危险操作）
        blacklist: 接口黑名单列表
        filter_status_codes: 过滤的状态码列表
        timeout: 请求超时时间（秒）
        max_threads: 最大线程数
    """
    proxy: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_params: Dict[str, str] = field(default_factory=dict)
    safe_mode: bool = True
    blacklist: List[str] = field(default_factory=list)
    filter_status_codes: List[int] = field(default_factory=list)
    timeout: int = 30
    max_threads: int = 10


@dataclass
class ExtractRule:
    """
    提取规则数据模型
    
    用于定义从响应中提取数据的规则，支持从 header、body 或 cookie 中提取。
    
    Attributes:
        source: 数据来源（header/body/cookie）
        pattern: 提取模式或正则表达式
        variable_name: 提取后存储的变量名
    """
    source: str
    pattern: str
    variable_name: str


@dataclass
class ChainStep:
    """
    请求链步骤数据模型
    
    用于表示请求链中的一个步骤，包括接口信息、提取规则和执行顺序。
    
    Attributes:
        step_id: 步骤唯一标识符
        endpoint: 接口信息
        extract_rules: 提取规则列表
        order: 执行顺序
    """
    step_id: str
    endpoint: APIEndpoint
    extract_rules: List[ExtractRule] = field(default_factory=list)
    order: int = 0


@dataclass
class RequestChain:
    """
    请求链数据模型
    
    用于定义一系列按顺序执行的 API 请求，支持从上一步骤提取数据传递给下一步骤。
    
    Attributes:
        chain_id: 链唯一标识符
        name: 链名称
        steps: 步骤列表
        enabled: 是否启用
    """
    chain_id: str
    name: str
    steps: List[ChainStep] = field(default_factory=list)
    enabled: bool = True
