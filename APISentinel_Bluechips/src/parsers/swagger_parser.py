"""
Swagger/OpenAPI 文档解析器

本模块提供解析 Swagger 2.0 和 OpenAPI 3.0 文档的功能。
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from ..core.models import APIEndpoint, Parameter


class SwaggerParser:
    """
    Swagger/OpenAPI 文档解析器
    
    支持解析 Swagger 2.0 和 OpenAPI 3.0 格式的 API 文档，
    从 URL 或本地文件加载并提取 API 接口信息。
    
    Attributes:
        timeout: 请求超时时间（秒）
        logger: 日志记录器
    """
    
    SUPPORTED_VERSIONS = ["2.0", "3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.1.0"]
    
    def __init__(self, timeout: int = 30):
        """
        初始化解析器
        
        Args:
            timeout: 请求超时时间（秒）
        """
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    def parse_from_url(self, url: str) -> List[APIEndpoint]:
        """
        从 URL 解析 Swagger/OpenAPI 文档
        
        Args:
            url: Swagger/OpenAPI 文档的 URL
            
        Returns:
            解析后的 APIEndpoint 列表
            
        Raises:
            ValueError: URL 格式无效
            requests.RequestException: 网络请求失败
            json.JSONDecodeError: JSON 格式无效
            NotImplementedError: 不支持的文档版本
        """
        self.logger.info(f"开始从 URL 解析文档: {url}")
        
        if not self._is_valid_url(url):
            raise ValueError(f"无效的 URL 格式: {url}")
        
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            version = self._detect_swagger_version(data)
            self.logger.info(f"检测到文档版本: {version}")
            
            if version.startswith("2."):
                endpoints = self._parse_swagger_2(data, url)
            elif version.startswith("3."):
                endpoints = self._parse_openapi_3(data, url)
            else:
                raise NotImplementedError(f"不支持的文档版本: {version}")
            
            self.logger.info(f"成功解析 {len(endpoints)} 个 API 接口")
            return endpoints
            
        except requests.RequestException as e:
            self.logger.error(f"网络请求失败: {e}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON 解析失败: {e}")
            raise
    
    def parse_from_file(self, file_path: str) -> List[APIEndpoint]:
        """
        从本地文件解析 Swagger/OpenAPI 文档
        
        Args:
            file_path: 本地文件路径
            
        Returns:
            解析后的 APIEndpoint 列表
            
        Raises:
            FileNotFoundError: 文件不存在
            json.JSONDecodeError: JSON 格式无效
            NotImplementedError: 不支持的文档版本
        """
        self.logger.info(f"开始从文件解析文档: {file_path}")
        
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            version = self._detect_swagger_version(data)
            self.logger.info(f"检测到文档版本: {version}")
            
            if version.startswith("2."):
                endpoints = self._parse_swagger_2(data)
            elif version.startswith("3."):
                endpoints = self._parse_openapi_3(data)
            else:
                raise NotImplementedError(f"不支持的文档版本: {version}")
            
            self.logger.info(f"成功解析 {len(endpoints)} 个 API 接口")
            return endpoints
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON 解析失败: {e}")
            raise
    
    def _detect_swagger_version(self, data: Dict[str, Any]) -> str:
        """
        检测 Swagger/OpenAPI 文档版本
        
        Args:
            data: 解析后的 JSON 数据
            
        Returns:
            版本字符串
            
        Raises:
            ValueError: 无法识别文档格式
        """
        if "swagger" in data:
            return data["swagger"]
        elif "openapi" in data:
            return data["openapi"]
        else:
            raise ValueError("无法识别的文档格式，缺少 swagger 或 openapi 字段")
    
    def _parse_swagger_2(self, data: Dict[str, Any], base_url: Optional[str] = None) -> List[APIEndpoint]:
        """
        解析 Swagger 2.0 文档
        
        Args:
            data: 解析后的 JSON 数据
            base_url: 基础 URL（用于构建完整 URL）
            
        Returns:
            APIEndpoint 列表
        """
        endpoints: List[APIEndpoint] = []
        
        host = data.get("host", "")
        base_path = data.get("basePath", "")
        schemes = data.get("schemes", ["http"])
        
        if base_url:
            parsed = urlparse(base_url)
            if not host:
                host = parsed.netloc
            if not schemes or schemes == ["http"]:
                schemes = [parsed.scheme] if parsed.scheme else ["http"]
        
        paths = data.get("paths", {})
        global_parameters = data.get("parameters", {})
        global_tags = {tag["name"]: tag.get("description", "") for tag in data.get("tags", [])}
        
        for path, path_item in paths.items():
            path_parameters = self._extract_parameters(path_item.get("parameters", []), global_parameters)
            
            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method not in path_item:
                    continue
                
                operation = path_item[method]
                
                operation_parameters = self._extract_parameters(
                    operation.get("parameters", []),
                    global_parameters
                )
                
                all_parameters = self._merge_parameters(path_parameters, operation_parameters)
                
                scheme = schemes[0] if schemes else "http"
                full_url = f"{scheme}://{host}{base_path}{path}"
                
                tags = operation.get("tags", [])
                description = operation.get("summary", "") or operation.get("description", "")
                
                endpoint = APIEndpoint(
                    url=full_url,
                    method=method.upper(),
                    path=path,
                    parameters=all_parameters,
                    headers={},
                    description=description,
                    tags=tags
                )
                
                endpoints.append(endpoint)
                self.logger.debug(f"解析接口: {method.upper()} {path}")
        
        return endpoints
    
    def _parse_openapi_3(self, data: Dict[str, Any], base_url: Optional[str] = None) -> List[APIEndpoint]:
        """
        解析 OpenAPI 3.0 文档
        
        Args:
            data: 解析后的 JSON 数据
            base_url: 基础 URL（用于构建完整 URL）
            global_tags: 全局标签字典
            
        Returns:
            APIEndpoint 列表
        """
        endpoints: List[APIEndpoint] = []
        
        servers = data.get("servers", [])
        if servers:
            base_server_url = servers[0].get("url", "")
        elif base_url:
            parsed = urlparse(base_url)
            base_server_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            base_server_url = ""
        
        paths = data.get("paths", {})
        global_tags = {tag["name"]: tag.get("description", "") for tag in data.get("tags", [])}
        
        for path, path_item in paths.items():
            path_parameters = self._extract_parameters_openapi3(path_item.get("parameters", []))
            
            for method in ["get", "post", "put", "delete", "patch", "options", "head", "trace"]:
                if method not in path_item:
                    continue
                
                operation = path_item[method]
                
                operation_parameters = self._extract_parameters_openapi3(
                    operation.get("parameters", [])
                )
                
                all_parameters = self._merge_parameters(path_parameters, operation_parameters)
                
                request_body = operation.get("requestBody", {})
                if request_body:
                    body_params = self._extract_request_body(request_body)
                    all_parameters.extend(body_params)
                
                if base_server_url:
                    full_url = urljoin(base_server_url, path)
                else:
                    full_url = path
                
                tags = operation.get("tags", [])
                description = operation.get("summary", "") or operation.get("description", "")
                
                endpoint = APIEndpoint(
                    url=full_url,
                    method=method.upper(),
                    path=path,
                    parameters=all_parameters,
                    headers={},
                    description=description,
                    tags=tags
                )
                
                endpoints.append(endpoint)
                self.logger.debug(f"解析接口: {method.upper()} {path}")
        
        return endpoints
    
    def _extract_parameters(
        self,
        param_list: List[Dict[str, Any]],
        global_parameters: Dict[str, Any] = None
    ) -> List[Parameter]:
        """
        从 Swagger 2.0 参数列表提取参数
        
        Args:
            param_list: 参数列表
            global_parameters: 全局参数定义
            
        Returns:
            Parameter 列表
        """
        parameters: List[Parameter] = []
        global_parameters = global_parameters or {}
        
        for param in param_list:
            if "$ref" in param:
                ref_name = param["$ref"].split("/")[-1]
                param = global_parameters.get(ref_name, {})
            
            param_type = param.get("in", "query")
            schema = param.get("schema", {})
            data_type = schema.get("type", param.get("type", "string"))
            
            parameter = Parameter(
                name=param.get("name", ""),
                param_type=param_type,
                data_type=data_type,
                required=param.get("required", False),
                default_value=param.get("default"),
                description=param.get("description", ""),
                example=param.get("example")
            )
            
            parameters.append(parameter)
        
        return parameters
    
    def _extract_parameters_openapi3(self, param_list: List[Dict[str, Any]]) -> List[Parameter]:
        """
        从 OpenAPI 3.0 参数列表提取参数
        
        Args:
            param_list: 参数列表
            
        Returns:
            Parameter 列表
        """
        parameters: List[Parameter] = []
        
        for param in param_list:
            schema = param.get("schema", {})
            data_type = schema.get("type", "string")
            
            parameter = Parameter(
                name=param.get("name", ""),
                param_type=param.get("in", "query"),
                data_type=data_type,
                required=param.get("required", False),
                default_value=schema.get("default") or param.get("default"),
                description=param.get("description", ""),
                example=param.get("example") or schema.get("example")
            )
            
            parameters.append(parameter)
        
        return parameters
    
    def _extract_request_body(self, request_body: Dict[str, Any]) -> List[Parameter]:
        """
        从 OpenAPI 3.0 requestBody 提取参数
        
        Args:
            request_body: requestBody 定义
            
        Returns:
            Parameter 列表
        """
        parameters: List[Parameter] = []
        
        content = request_body.get("content", {})
        
        for content_type, content_schema in content.items():
            schema = content_schema.get("schema", {})
            properties = schema.get("properties", {})
            required_fields = schema.get("required", [])
            
            if content_type in ["application/json", "application/x-www-form-urlencoded"]:
                for prop_name, prop_schema in properties.items():
                    parameter = Parameter(
                        name=prop_name,
                        param_type="body",
                        data_type=prop_schema.get("type", "string"),
                        required=prop_name in required_fields,
                        default_value=prop_schema.get("default"),
                        description=prop_schema.get("description", ""),
                        example=prop_schema.get("example")
                    )
                    parameters.append(parameter)
            elif content_type.startswith("multipart/"):
                parameter = Parameter(
                    name="requestBody",
                    param_type="body",
                    data_type="file",
                    required=request_body.get("required", False),
                    default_value=None,
                    description=request_body.get("description", ""),
                    example=None
                )
                parameters.append(parameter)
                break
        
        return parameters
    
    def _merge_parameters(
        self,
        path_params: List[Parameter],
        operation_params: List[Parameter]
    ) -> List[Parameter]:
        """
        合并路径参数和操作参数
        
        操作参数会覆盖同名的路径参数。
        
        Args:
            path_params: 路径级别的参数
            operation_params: 操作级别的参数
            
        Returns:
            合并后的参数列表
        """
        param_dict = {}
        
        for param in path_params:
            key = f"{param.param_type}_{param.name}"
            param_dict[key] = param
        
        for param in operation_params:
            key = f"{param.param_type}_{param.name}"
            param_dict[key] = param
        
        return list(param_dict.values())
    
    def _is_valid_url(self, url: str) -> bool:
        """
        验证 URL 格式是否有效
        
        Args:
            url: 要验证的 URL
            
        Returns:
            是否有效
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
