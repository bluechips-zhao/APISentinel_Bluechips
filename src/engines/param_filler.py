"""
参数智能识别与填充模块

本模块实现参数智能识别与填充功能，根据参数名称自动识别类型并生成合适的测试值。
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core.models import APIEndpoint, Parameter


logger = logging.getLogger(__name__)


class ParamFiller:
    """
    参数智能识别与填充类
    
    根据参数名称自动识别参数类型，并生成合适的测试值。
    支持自定义参数值配置，自定义值优先级高于自动生成。
    
    Attributes:
        _custom_values: 自定义参数值字典
        _pattern_rules: 参数类型识别规则字典
    """
    
    def __init__(self):
        """初始化 ParamFiller"""
        self._custom_values: Dict[str, Any] = {}
        self._pattern_rules: Dict[str, List[str]] = {
            "id": ["user_id", "order_id", "account_id", "id", "uid", "item_id", "product_id", "record_id"],
            "email": ["email", "mail", "user_email", "email_address", "e_mail"],
            "phone": ["phone", "mobile", "tel", "telephone", "cellphone", "phone_number", "mobile_number"],
            "username": ["username", "user_name", "login_name", "login", "account", "account_name"],
            "password": ["password", "pwd", "pass", "user_password", "login_password", "passwd"],
            "name": ["name", "username", "nickname", "display_name", "full_name", "real_name", "user_name"],
            "date": ["date", "created_at", "updated_at", "deleted_at", "start_date", "end_date", "birth_date", "create_time", "update_time"],
            "url": ["url", "link", "website", "web_url", "page_url", "redirect_url", "callback_url"],
            "boolean": ["is_active", "enabled", "status", "is_enabled", "is_deleted", "is_valid", "active", "visible", "is_public"],
            "page": ["page", "page_num", "page_no", "current_page", "pagenumber"],
            "size": ["size", "page_size", "limit", "per_page", "page_size", "pagesize", "perpage"],
            "token": ["token", "access_token", "auth_token", "api_token", "bearer_token", "refresh_token", "csrf_token"],
        }
        self._type_generators: Dict[str, Any] = {
            "id": lambda: 1,
            "email": lambda: "test@example.com",
            "phone": lambda: "13800138000",
            "username": lambda: "testuser",
            "password": lambda: "Test@123456",
            "name": lambda: "Test User",
            "date": lambda: datetime.now().strftime("%Y-%m-%d"),
            "url": lambda: "http://example.com",
            "boolean": lambda: True,
            "page": lambda: 1,
            "size": lambda: 10,
            "token": lambda: "test_token_123",
        }
        logger.info("ParamFiller 初始化完成")
    
    def _match_pattern(self, param_name: str) -> Optional[str]:
        """
        匹配参数名称对应的类型
        
        Args:
            param_name: 参数名称
            
        Returns:
            匹配到的参数类型，如果未匹配则返回 None
        """
        param_lower = param_name.lower()
        
        for param_type, patterns in self._pattern_rules.items():
            for pattern in patterns:
                if param_lower == pattern.lower():
                    logger.debug(f"参数 '{param_name}' 精确匹配类型: {param_type}")
                    return param_type
        
        best_match = None
        best_match_length = 0
        
        for param_type, patterns in self._pattern_rules.items():
            for pattern in patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in param_lower:
                    if len(pattern_lower) > best_match_length:
                        best_match = param_type
                        best_match_length = len(pattern_lower)
        
        if best_match:
            logger.debug(f"参数 '{param_name}' 部分匹配类型: {best_match}")
            return best_match
        
        for param_type, patterns in self._pattern_rules.items():
            for pattern in patterns:
                pattern_keywords = pattern.lower().split("_")
                if any(keyword in param_lower for keyword in pattern_keywords if len(keyword) > 2):
                    logger.debug(f"参数 '{param_name}' 关键词匹配类型: {param_type}")
                    return param_type
        
        logger.debug(f"参数 '{param_name}' 未匹配到任何类型")
        return None
    
    def _generate_by_type(self, data_type: str) -> Any:
        """
        根据数据类型生成默认值
        
        Args:
            data_type: 数据类型（string/integer/boolean等）
            
        Returns:
            生成的默认值
        """
        type_mapping = {
            "string": "",
            "str": "",
            "integer": 0,
            "int": 0,
            "long": 0,
            "float": 0.0,
            "double": 0.0,
            "boolean": False,
            "bool": False,
            "array": [],
            "list": [],
            "object": {},
            "dict": {},
            "file": "",
        }
        
        data_type_lower = data_type.lower() if data_type else "string"
        value = type_mapping.get(data_type_lower, "")
        logger.debug(f"数据类型 '{data_type}' 生成默认值: {value}")
        return value
    
    def generate_value(self, param_name: str, param_type: Optional[str] = None) -> Any:
        """
        根据参数名称生成值
        
        优先级：
        1. 自定义参数值
        2. 参数名称模式匹配
        3. 数据类型默认值
        
        Args:
            param_name: 参数名称
            param_type: 数据类型（可选）
            
        Returns:
            生成的参数值
        """
        if param_name in self._custom_values:
            value = self._custom_values[param_name]
            logger.debug(f"使用自定义值 '{value}' 用于参数 '{param_name}'")
            return value
        
        matched_type = self._match_pattern(param_name)
        if matched_type:
            value = self._type_generators[matched_type]()
            logger.debug(f"参数 '{param_name}' 生成值: {value} (类型: {matched_type})")
            return value
        
        if param_type:
            value = self._generate_by_type(param_type)
            logger.debug(f"参数 '{param_name}' 根据数据类型 '{param_type}' 生成值: {value}")
            return value
        
        logger.debug(f"参数 '{param_name}' 使用默认空字符串")
        return ""
    
    def set_custom_value(self, param_name: str, value: Any) -> None:
        """
        设置自定义参数值
        
        Args:
            param_name: 参数名称
            value: 参数值
        """
        self._custom_values[param_name] = value
        logger.info(f"设置自定义参数值: {param_name} = {value}")
    
    def get_custom_value(self, param_name: str) -> Optional[Any]:
        """
        获取自定义参数值
        
        Args:
            param_name: 参数名称
            
        Returns:
            自定义参数值，如果不存在则返回 None
        """
        return self._custom_values.get(param_name)
    
    def clear_custom_values(self) -> None:
        """清空所有自定义参数值"""
        self._custom_values.clear()
        logger.info("已清空所有自定义参数值")
    
    def fill_parameters(self, parameters: List[Parameter]) -> Dict[str, Any]:
        """
        填充参数列表
        
        Args:
            parameters: 参数列表
            
        Returns:
            参数名称到值的映射字典
        """
        result: Dict[str, Any] = {}
        
        for param in parameters:
            if param.default_value is not None:
                result[param.name] = param.default_value
                logger.debug(f"参数 '{param.name}' 使用默认值: {param.default_value}")
            elif param.example is not None:
                result[param.name] = param.example
                logger.debug(f"参数 '{param.name}' 使用示例值: {param.example}")
            else:
                result[param.name] = self.generate_value(param.name, param.data_type)
        
        logger.info(f"已填充 {len(result)} 个参数")
        return result
    
    def fill_endpoint(self, endpoint: APIEndpoint) -> Dict[str, Any]:
        """
        填充接口参数
        
        Args:
            endpoint: API 接口对象
            
        Returns:
            参数名称到值的映射字典
        """
        logger.info(f"开始填充接口参数: {endpoint.method} {endpoint.path}")
        
        result = self.fill_parameters(endpoint.parameters)
        
        query_params = {}
        body_params = {}
        path_params = {}
        header_params = {}
        
        for param in endpoint.parameters:
            if param.name in result:
                value = result[param.name]
                
                if param.param_type == "query":
                    query_params[param.name] = value
                elif param.param_type == "body":
                    body_params[param.name] = value
                elif param.param_type == "path":
                    path_params[param.name] = value
                elif param.param_type == "header":
                    header_params[param.name] = value
        
        filled_result = {
            "query": query_params,
            "body": body_params,
            "path": path_params,
            "header": header_params,
            "all": result,
        }
        
        logger.info(
            f"接口参数填充完成 - Query: {len(query_params)}, "
            f"Body: {len(body_params)}, Path: {len(path_params)}, "
            f"Header: {len(header_params)}"
        )
        
        return filled_result
    
    def add_pattern_rule(self, param_type: str, patterns: List[str]) -> None:
        """
        添加参数类型识别规则
        
        Args:
            param_type: 参数类型
            patterns: 参数名称模式列表
        """
        if param_type not in self._pattern_rules:
            self._pattern_rules[param_type] = []
        
        self._pattern_rules[param_type].extend(patterns)
        logger.info(f"添加参数类型识别规则: {param_type} -> {patterns}")
    
    def set_type_generator(self, param_type: str, generator: Any) -> None:
        """
        设置类型值生成器
        
        Args:
            param_type: 参数类型
            generator: 值生成器（函数或值）
        """
        if callable(generator):
            self._type_generators[param_type] = generator
        else:
            self._type_generators[param_type] = lambda: generator
        
        logger.info(f"设置类型值生成器: {param_type}")
    
    def get_pattern_rules(self) -> Dict[str, List[str]]:
        """
        获取所有参数类型识别规则
        
        Returns:
            参数类型识别规则字典
        """
        return self._pattern_rules.copy()
    
    def get_custom_values(self) -> Dict[str, Any]:
        """
        获取所有自定义参数值
        
        Returns:
            自定义参数值字典
        """
        return self._custom_values.copy()
