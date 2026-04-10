"""
多格式请求构造器模块

本模块实现多格式请求构造功能，支持 Query String、JSON Body 和 Form Body 三种格式。
"""

import json
import logging
from typing import Any, Dict, List
from urllib.parse import urlencode, quote

from ..core.models import APIEndpoint


logger = logging.getLogger(__name__)


class RequestBuilder:
    """
    多格式请求构造类
    
    支持构造 Query String、JSON Body 和 Form Body 三种格式的请求。
    根据 HTTP 方法自动选择合适的请求格式。
    
    Attributes:
        _param_filler: 参数填充器实例（可选）
    """
    
    def __init__(self, param_filler=None):
        """
        初始化 RequestBuilder
        
        Args:
            param_filler: 参数填充器实例（可选），用于自动填充参数值
        """
        self._param_filler = param_filler
        logger.info("RequestBuilder 初始化完成")
    
    def build_query_params(self, params: Dict[str, Any]) -> str:
        """
        构造 Query String
        
        将参数转换为 key1=value1&key2=value2 格式，自动进行 URL 编码。
        
        Args:
            params: 参数字典
            
        Returns:
            Query String 字符串
            
        Example:
            >>> builder = RequestBuilder()
            >>> builder.build_query_params({"user_id": 1, "name": "test"})
            "user_id=1&name=test"
        """
        if not params:
            logger.debug("Query 参数为空，返回空字符串")
            return ""
        
        encoded_params = []
        for key, value in params.items():
            if value is not None:
                encoded_params.append((key, value))
        
        query_string = urlencode(encoded_params, doseq=True)
        logger.debug(f"构造 Query String: {query_string}")
        return query_string
    
    def build_json_body(self, params: Dict[str, Any]) -> str:
        """
        构造 JSON Body
        
        将参数转换为 JSON 字符串格式。
        
        Args:
            params: 参数字典
            
        Returns:
            JSON 字符串
            
        Example:
            >>> builder = RequestBuilder()
            >>> builder.build_json_body({"user_id": 1, "name": "test"})
            '{"user_id": 1, "name": "test"}'
        """
        if not params:
            logger.debug("JSON Body 参数为空，返回空字符串")
            return ""
        
        json_body = json.dumps(params, ensure_ascii=False)
        logger.debug(f"构造 JSON Body: {json_body}")
        return json_body
    
    def build_form_body(self, params: Dict[str, Any]) -> str:
        """
        构造 Form Body
        
        将参数转换为 key1=value1&key2=value2 格式，自动进行 URL 编码。
        
        Args:
            params: 参数字典
            
        Returns:
            Form Body 字符串
            
        Example:
            >>> builder = RequestBuilder()
            >>> builder.build_form_body({"user_id": 1, "name": "test"})
            "user_id=1&name=test"
        """
        if not params:
            logger.debug("Form Body 参数为空，返回空字符串")
            return ""
        
        form_body = urlencode(params, doseq=True)
        logger.debug(f"构造 Form Body: {form_body}")
        return form_body
    
    def _get_params_by_type(self, endpoint: APIEndpoint, param_type: str) -> Dict[str, Any]:
        """
        从接口中获取指定类型的参数
        
        Args:
            endpoint: API 接口对象
            param_type: 参数类型（query/body/path/header）
            
        Returns:
            参数字典
        """
        params = {}
        for param in endpoint.parameters:
            if param.param_type == param_type:
                if param.default_value is not None:
                    params[param.name] = param.default_value
                elif param.example is not None:
                    params[param.name] = param.example
                elif self._param_filler:
                    params[param.name] = self._param_filler.generate_value(
                        param.name, param.data_type
                    )
                else:
                    params[param.name] = self._get_default_value(param.data_type)
        
        logger.debug(f"从接口获取 {param_type} 类型参数: {len(params)} 个")
        return params
    
    def _get_default_value(self, data_type: str) -> Any:
        """
        根据数据类型获取默认值
        
        Args:
            data_type: 数据类型
            
        Returns:
            默认值
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
        }
        
        data_type_lower = data_type.lower() if data_type else "string"
        return type_mapping.get(data_type_lower, "")
    
    def _build_url_with_query(self, base_url: str, query_params: str) -> str:
        """
        构造带 Query 参数的完整 URL
        
        Args:
            base_url: 基础 URL
            query_params: Query 参数字符串
            
        Returns:
            完整 URL
        """
        if not query_params:
            return base_url
        
        separator = "&" if "?" in base_url else "?"
        return f"{base_url}{separator}{query_params}"
    
    def build_request(self, endpoint: APIEndpoint, format: str = "auto") -> Dict[str, Any]:
        """
        构造请求
        
        根据指定的格式构造请求，支持 "query"、"json"、"form" 和 "auto" 四种模式。
        当 format 为 "auto" 时，根据 HTTP 方法自动选择合适的格式。
        
        Args:
            endpoint: API 接口对象
            format: 请求格式（"query"/"json"/"form"/"auto"）
            
        Returns:
            包含 url、method、headers、body 的字典
            
        支持的 HTTP 方法：
            - GET: 使用 Query String
            - POST: 使用 JSON Body 或 Form Body（根据 Content-Type 判断）
            - PUT: 使用 JSON Body 或 Form Body
            - DELETE: 使用 Query String 或 Body
            - PATCH: 使用 JSON Body
        """
        logger.info(f"开始构造请求: {endpoint.method} {endpoint.path}, 格式: {format}")
        
        method = endpoint.method.upper()
        
        if format == "auto":
            format = self._determine_format(method, endpoint)
            logger.debug(f"自动选择格式: {format}")
        
        request = {
            "url": endpoint.url,
            "method": method,
            "headers": dict(endpoint.headers),
            "body": "",
        }
        
        if format == "query":
            request = self._build_query_request(endpoint, request)
        elif format == "json":
            request = self._build_json_request(endpoint, request)
        elif format == "form":
            request = self._build_form_request(endpoint, request)
        else:
            logger.warning(f"未知的请求格式: {format}，使用 Query 格式")
            request = self._build_query_request(endpoint, request)
        
        logger.info(f"请求构造完成: {method} {request['url']}")
        return request
    
    def _determine_format(self, method: str, endpoint: APIEndpoint) -> str:
        """
        根据 HTTP 方法和接口信息确定请求格式
        
        Args:
            method: HTTP 方法
            endpoint: API 接口对象
            
        Returns:
            请求格式（"query"/"json"/"form"）
        """
        if method == "GET":
            return "query"
        elif method == "POST":
            content_type = endpoint.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return "json"
            elif "application/x-www-form-urlencoded" in content_type:
                return "form"
            else:
                return "json"
        elif method == "PUT":
            content_type = endpoint.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                return "form"
            else:
                return "json"
        elif method == "DELETE":
            body_params = self._get_params_by_type(endpoint, "body")
            if body_params:
                return "json"
            else:
                return "query"
        elif method == "PATCH":
            return "json"
        else:
            return "query"
    
    def _build_query_request(self, endpoint: APIEndpoint, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        构造 Query 格式请求
        
        Args:
            endpoint: API 接口对象
            request: 基础请求字典
            
        Returns:
            完整请求字典
        """
        query_params_dict = self._get_params_by_type(endpoint, "query")
        query_params = self.build_query_params(query_params_dict)
        
        request["url"] = self._build_url_with_query(endpoint.url, query_params)
        request["body"] = ""
        
        return request
    
    def _build_json_request(self, endpoint: APIEndpoint, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        构造 JSON 格式请求
        
        Args:
            endpoint: API 接口对象
            request: 基础请求字典
            
        Returns:
            完整请求字典
        """
        query_params_dict = self._get_params_by_type(endpoint, "query")
        query_params = self.build_query_params(query_params_dict)
        
        body_params_dict = self._get_params_by_type(endpoint, "body")
        request["body"] = self.build_json_body(body_params_dict)
        
        request["url"] = self._build_url_with_query(endpoint.url, query_params)
        request["headers"]["Content-Type"] = "application/json"
        
        return request
    
    def _build_form_request(self, endpoint: APIEndpoint, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        构造 Form 格式请求
        
        Args:
            endpoint: API 接口对象
            request: 基础请求字典
            
        Returns:
            完整请求字典
        """
        query_params_dict = self._get_params_by_type(endpoint, "query")
        query_params = self.build_query_params(query_params_dict)
        
        body_params_dict = self._get_params_by_type(endpoint, "body")
        request["body"] = self.build_form_body(body_params_dict)
        
        request["url"] = self._build_url_with_query(endpoint.url, query_params)
        request["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
        
        return request
    
    def build_all_formats(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """
        构造所有格式的请求
        
        为同一个接口构造 Query、JSON 和 Form 三种格式的请求。
        
        Args:
            endpoint: API 接口对象
            
        Returns:
            包含三种格式请求的列表
        """
        logger.info(f"开始构造所有格式的请求: {endpoint.method} {endpoint.path}")
        
        requests = []
        
        query_request = self.build_request(endpoint, format="query")
        query_request["format"] = "query"
        requests.append(query_request)
        
        json_request = self.build_request(endpoint, format="json")
        json_request["format"] = "json"
        requests.append(json_request)
        
        form_request = self.build_request(endpoint, format="form")
        form_request["format"] = "form"
        requests.append(form_request)
        
        logger.info(f"已构造 {len(requests)} 种格式的请求")
        return requests
