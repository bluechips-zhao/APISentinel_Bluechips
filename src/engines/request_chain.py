"""
请求链执行器模块

本模块实现请求链功能，支持按顺序执行多个 API 请求，并在步骤之间传递变量。
"""

import json
import logging
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..core.http_client import HttpClient, HttpClientError
from ..core.models import (
    APIEndpoint,
    ChainStep,
    ExtractRule,
    Parameter,
    RequestChain,
    TestResult,
)
from .request_builder import RequestBuilder


logger = logging.getLogger(__name__)


class RequestChainExecutor:
    """
    请求链执行器
    
    支持按顺序执行多个 API 请求，并在步骤之间传递变量。
    支持从响应中提取数据（header/body/cookie），并注入到后续请求中。
    
    Attributes:
        _chains: 请求链字典
        _variable_pool: 变量池
        _chain_results: 请求链执行结果缓存
        _request_builder: 请求构造器
    """
    
    def __init__(self, request_builder: Optional[RequestBuilder] = None):
        """
        初始化 RequestChainExecutor
        
        Args:
            request_builder: 请求构造器实例（可选）
        """
        self._chains: Dict[str, RequestChain] = {}
        self._variable_pool: Dict[str, str] = {}
        self._chain_results: Dict[str, List[TestResult]] = {}
        self._request_builder = request_builder or RequestBuilder()
        
        logger.info("RequestChainExecutor 初始化完成")
    
    def create_chain(self, name: str, steps: List[ChainStep]) -> RequestChain:
        """
        创建请求链
        
        Args:
            name: 链名称
            steps: 步骤列表
            
        Returns:
            创建的 RequestChain 对象
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> step = ChainStep(
            ...     step_id="step1",
            ...     endpoint=APIEndpoint(url="https://api.example.com/login", method="POST", path="/login"),
            ...     extract_rules=[ExtractRule(source="body", pattern=r'"token":"([^"]+)"', variable_name="auth_token")]
            ... )
            >>> chain = executor.create_chain("Login Chain", [step])
        """
        chain_id = str(uuid.uuid4())
        
        sorted_steps = sorted(steps, key=lambda s: s.order)
        
        chain = RequestChain(
            chain_id=chain_id,
            name=name,
            steps=sorted_steps,
            enabled=True,
        )
        
        self._chains[chain_id] = chain
        logger.info(f"创建请求链: {name}, chain_id={chain_id}, 步骤数={len(steps)}")
        
        return chain
    
    def load_chain(self, chain_data: Dict[str, Any]) -> RequestChain:
        """
        从字典加载请求链
        
        Args:
            chain_data: 请求链数据字典
            
        Returns:
            RequestChain 对象
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> chain_data = {
            ...     "chain_id": "chain-001",
            ...     "name": "Test Chain",
            ...     "steps": [...],
            ...     "enabled": True
            ... }
            >>> chain = executor.load_chain(chain_data)
        """
        steps = []
        for step_data in chain_data.get("steps", []):
            endpoint_data = step_data.get("endpoint", {})
            
            parameters = []
            for param_data in endpoint_data.get("parameters", []):
                param = Parameter(
                    name=param_data.get("name", ""),
                    param_type=param_data.get("param_type", "query"),
                    data_type=param_data.get("data_type", "string"),
                    required=param_data.get("required", False),
                    default_value=param_data.get("default_value"),
                    description=param_data.get("description", ""),
                    example=param_data.get("example"),
                )
                parameters.append(param)
            
            endpoint = APIEndpoint(
                url=endpoint_data.get("url", ""),
                method=endpoint_data.get("method", "GET"),
                path=endpoint_data.get("path", ""),
                parameters=parameters,
                headers=endpoint_data.get("headers", {}),
                description=endpoint_data.get("description", ""),
                tags=endpoint_data.get("tags", []),
            )
            
            extract_rules = []
            for rule_data in step_data.get("extract_rules", []):
                rule = ExtractRule(
                    source=rule_data.get("source", "body"),
                    pattern=rule_data.get("pattern", ""),
                    variable_name=rule_data.get("variable_name", ""),
                )
                extract_rules.append(rule)
            
            step = ChainStep(
                step_id=step_data.get("step_id", str(uuid.uuid4())),
                endpoint=endpoint,
                extract_rules=extract_rules,
                order=step_data.get("order", 0),
            )
            steps.append(step)
        
        chain = RequestChain(
            chain_id=chain_data.get("chain_id", str(uuid.uuid4())),
            name=chain_data.get("name", "Unnamed Chain"),
            steps=steps,
            enabled=chain_data.get("enabled", True),
        )
        
        self._chains[chain.chain_id] = chain
        logger.info(f"加载请求链: {chain.name}, chain_id={chain.chain_id}")
        
        return chain
    
    def save_chain(self, chain: RequestChain) -> Dict[str, Any]:
        """
        保存请求链为字典
        
        Args:
            chain: RequestChain 对象
            
        Returns:
            请求链数据字典
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> chain_data = executor.save_chain(chain)
        """
        steps_data = []
        for step in chain.steps:
            parameters_data = []
            for param in step.endpoint.parameters:
                param_data = {
                    "name": param.name,
                    "param_type": param.param_type,
                    "data_type": param.data_type,
                    "required": param.required,
                    "default_value": param.default_value,
                    "description": param.description,
                    "example": param.example,
                }
                parameters_data.append(param_data)
            
            endpoint_data = {
                "url": step.endpoint.url,
                "method": step.endpoint.method,
                "path": step.endpoint.path,
                "parameters": parameters_data,
                "headers": step.endpoint.headers,
                "description": step.endpoint.description,
                "tags": step.endpoint.tags,
            }
            
            extract_rules_data = []
            for rule in step.extract_rules:
                rule_data = {
                    "source": rule.source,
                    "pattern": rule.pattern,
                    "variable_name": rule.variable_name,
                }
                extract_rules_data.append(rule_data)
            
            step_data = {
                "step_id": step.step_id,
                "endpoint": endpoint_data,
                "extract_rules": extract_rules_data,
                "order": step.order,
            }
            steps_data.append(step_data)
        
        chain_data = {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "steps": steps_data,
            "enabled": chain.enabled,
        }
        
        logger.debug(f"保存请求链: {chain.name}, chain_id={chain.chain_id}")
        return chain_data
    
    def load_chains_from_file(self, file_path: str) -> List[RequestChain]:
        """
        从文件加载请求链列表
        
        Args:
            file_path: 文件路径
            
        Returns:
            RequestChain 列表
            
        Raises:
            FileNotFoundError: 文件不存在
            json.JSONDecodeError: JSON 解析失败
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> chains = executor.load_chains_from_file("chains.json")
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        chains = []
        chain_list = data if isinstance(data, list) else [data]
        
        for chain_data in chain_list:
            chain = self.load_chain(chain_data)
            chains.append(chain)
        
        logger.info(f"从文件加载 {len(chains)} 个请求链: {file_path}")
        return chains
    
    def save_chains_to_file(self, chains: List[RequestChain], file_path: str) -> None:
        """
        保存请求链列表到文件
        
        Args:
            chains: RequestChain 列表
            file_path: 文件路径
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> executor.save_chains_to_file(chains, "chains.json")
        """
        chains_data = [self.save_chain(chain) for chain in chains]
        
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(chains_data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"保存 {len(chains)} 个请求链到文件: {file_path}")
    
    def extract_value(self, response: requests.Response, rule: ExtractRule) -> Optional[str]:
        """
        从响应中提取值
        
        支持从 header、body 和 cookie 中提取数据。
        
        Args:
            response: HTTP 响应对象
            rule: 提取规则
            
        Returns:
            提取的值，如果未找到则返回 None
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> rule = ExtractRule(source="body", pattern=r'"token":"([^"]+)"', variable_name="token")
            >>> value = executor.extract_value(response, rule)
        """
        try:
            if rule.source == "header":
                return self._extract_from_header(response, rule)
            elif rule.source == "body":
                return self._extract_from_body(response, rule)
            elif rule.source == "cookie":
                return self._extract_from_cookie(response, rule)
            else:
                logger.warning(f"未知的提取来源: {rule.source}")
                return None
        except Exception as e:
            logger.error(f"提取值失败: {e}, rule={rule}")
            return None
    
    def _extract_from_header(self, response: requests.Response, rule: ExtractRule) -> Optional[str]:
        """
        从响应头中提取值
        
        Args:
            response: HTTP 响应对象
            rule: 提取规则
            
        Returns:
            提取的值
        """
        header_name = rule.pattern.split(":")[0] if ":" in rule.pattern else rule.pattern
        
        if ":" in rule.pattern:
            header_name, pattern = rule.pattern.split(":", 1)
            header_value = response.headers.get(header_name, "")
            match = re.search(pattern.strip(), header_value)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        else:
            return response.headers.get(rule.pattern)
        
        return None
    
    def _extract_from_body(self, response: requests.Response, rule: ExtractRule) -> Optional[str]:
        """
        从响应体中提取值
        
        支持正则表达式和 JSONPath 两种方式。
        
        Args:
            response: HTTP 响应对象
            rule: 提取规则
            
        Returns:
            提取的值
        """
        body = response.text
        
        if rule.pattern.startswith("$.") or rule.pattern.startswith("$["):
            return self._extract_by_jsonpath(body, rule.pattern)
        else:
            return self._extract_by_regex(body, rule.pattern)
    
    def _extract_by_regex(self, text: str, pattern: str) -> Optional[str]:
        """
        使用正则表达式提取值
        
        Args:
            text: 文本内容
            pattern: 正则表达式
            
        Returns:
            提取的值
        """
        match = re.search(pattern, text)
        if match:
            return match.group(1) if match.groups() else match.group(0)
        return None
    
    def _extract_by_jsonpath(self, text: str, jsonpath: str) -> Optional[str]:
        """
        使用 JSONPath 提取值
        
        简化实现，支持基本的 JSONPath 语法：
        - $.key1.key2
        - $.key1[0]
        - $.key1[0].key2
        
        Args:
            text: JSON 文本
            jsonpath: JSONPath 表达式
            
        Returns:
            提取的值
        """
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("响应体不是有效的 JSON")
            return None
        
        path = jsonpath
        if path.startswith("$."):
            path = path[2:]
        
        keys = re.split(r'\.|\[|\]', path)
        keys = [k for k in keys if k]
        
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list):
                try:
                    index = int(key)
                    current = current[index]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            
            if current is None:
                return None
        
        return str(current) if current is not None else None
    
    def _extract_from_cookie(self, response: requests.Response, rule: ExtractRule) -> Optional[str]:
        """
        从 Cookie 中提取值
        
        Args:
            response: HTTP 响应对象
            rule: 提取规则
            
        Returns:
            提取的值
        """
        cookies = response.cookies
        
        if rule.pattern in cookies:
            return cookies.get(rule.pattern)
        
        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            cookie_pattern = rf'{rule.pattern}=([^;]+)'
            match = re.search(cookie_pattern, set_cookie)
            if match:
                return match.group(1)
        
        return None
    
    def _replace_variables(self, text: str, variables: Dict[str, str]) -> str:
        """
        替换文本中的变量占位符
        
        支持 {{variable_name}} 格式的变量替换。
        
        Args:
            text: 原始文本
            variables: 变量字典
            
        Returns:
            替换后的文本
        """
        if not text:
            return text
        
        def replace_match(match):
            var_name = match.group(1).strip()
            value = variables.get(var_name, match.group(0))
            return str(value)
        
        return re.sub(r'\{\{(\w+)\}\}', replace_match, text)
    
    def _inject_variables_to_endpoint(
        self,
        endpoint: APIEndpoint,
        variables: Dict[str, str]
    ) -> APIEndpoint:
        """
        将变量注入到接口中
        
        Args:
            endpoint: 原始接口对象
            variables: 变量字典
            
        Returns:
            注入变量后的新接口对象
        """
        new_url = self._replace_variables(endpoint.url, variables)
        new_headers = {
            key: self._replace_variables(value, variables)
            for key, value in endpoint.headers.items()
        }
        
        new_parameters = []
        for param in endpoint.parameters:
            new_default_value = param.default_value
            if new_default_value is not None:
                new_default_value = self._replace_variables(str(new_default_value), variables)
            
            new_example = param.example
            if new_example is not None:
                new_example = self._replace_variables(str(new_example), variables)
            
            new_param = Parameter(
                name=param.name,
                param_type=param.param_type,
                data_type=param.data_type,
                required=param.required,
                default_value=new_default_value,
                description=param.description,
                example=new_example,
            )
            new_parameters.append(new_param)
        
        return APIEndpoint(
            url=new_url,
            method=endpoint.method,
            path=endpoint.path,
            parameters=new_parameters,
            headers=new_headers,
            description=endpoint.description,
            tags=endpoint.tags,
        )
    
    def execute_chain(
        self,
        chain: RequestChain,
        http_client: HttpClient,
        stop_on_error: bool = True
    ) -> List[TestResult]:
        """
        执行请求链
        
        按顺序执行请求链中的每个步骤，支持变量传递和错误处理。
        
        Args:
            chain: RequestChain 对象
            http_client: HTTP 客户端实例
            stop_on_error: 某步失败时是否停止执行，默认 True
            
        Returns:
            TestResult 列表
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> with HttpClient() as client:
            ...     results = executor.execute_chain(chain, client)
        """
        if not chain.enabled:
            logger.warning(f"请求链已禁用: {chain.name}")
            return []
        
        logger.info(f"开始执行请求链: {chain.name}, chain_id={chain.chain_id}, 步骤数={len(chain.steps)}")
        
        results: List[TestResult] = []
        local_variables: Dict[str, str] = dict(self._variable_pool)
        
        for step in chain.steps:
            logger.info(f"执行步骤 {step.order + 1}/{len(chain.steps)}: {step.step_id}")
            
            injected_endpoint = self._inject_variables_to_endpoint(
                step.endpoint, local_variables
            )
            
            result = self._execute_step(step, injected_endpoint, http_client)
            results.append(result)
            
            if result.error:
                logger.error(f"步骤执行失败: {step.step_id}, error={result.error}")
                if stop_on_error:
                    logger.warning(f"请求链执行中断: {chain.name}")
                    break
            else:
                for rule in step.extract_rules:
                    try:
                        response = http_client._session
                        fake_response = self._create_fake_response(result)
                        value = self.extract_value(fake_response, rule)
                        if value:
                            local_variables[rule.variable_name] = value
                            logger.info(f"提取变量: {rule.variable_name} = {value[:50]}...")
                    except Exception as e:
                        logger.error(f"变量提取失败: {rule.variable_name}, error={e}")
        
        self._chain_results[chain.chain_id] = results
        self._variable_pool.update(local_variables)
        
        success_count = sum(1 for r in results if not r.error)
        logger.info(
            f"请求链执行完成: {chain.name}, "
            f"成功={success_count}/{len(results)}, "
            f"变量数={len(local_variables)}"
        )
        
        return results
    
    def _create_fake_response(self, result: TestResult) -> requests.Response:
        """
        创建模拟的 Response 对象用于变量提取
        
        Args:
            result: 测试结果对象
            
        Returns:
            模拟的 Response 对象
        """
        response = requests.Response()
        response.status_code = result.response_status
        response.headers = requests.structures.CaseInsensitiveDict(result.response_headers)
        response._content = result.response_body.encode("utf-8") if result.response_body else b""
        response.cookies = requests.cookies.RequestsCookieJar()
        
        return response
    
    def _execute_step(
        self,
        step: ChainStep,
        endpoint: APIEndpoint,
        http_client: HttpClient
    ) -> TestResult:
        """
        执行单个步骤
        
        Args:
            step: 步骤对象
            endpoint: 接口对象
            http_client: HTTP 客户端
            
        Returns:
            TestResult 对象
        """
        request_id = str(uuid.uuid4())
        logger.info(f"执行步骤: {step.step_id}, request_id={request_id}")
        
        request_data = self._request_builder.build_request(endpoint)
        
        request_headers = request_data["headers"]
        request_body = request_data["body"]
        
        start_time = time.time()
        error_msg = ""
        response_status = 0
        response_headers: Dict[str, str] = {}
        response_body = ""
        response_length = 0
        
        try:
            kwargs = {
                "headers": request_headers,
                "timeout": http_client.timeout,
            }
            
            if request_body:
                kwargs["data"] = request_body
            
            response = http_client.request(
                method=request_data["method"],
                url=request_data["url"],
                **kwargs
            )
            
            response_status = response.status_code
            response_headers = dict(response.headers)
            response_body = response.text
            response_length = len(response.content)
            
            logger.info(
                f"步骤执行成功: {step.step_id} - "
                f"状态码: {response_status}, 响应大小: {response_length} 字节"
            )
            
        except HttpClientError as e:
            error_msg = str(e)
            logger.error(f"步骤执行失败: {step.step_id} - {error_msg}")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"步骤执行异常: {step.step_id} - {error_msg}")
        
        end_time = time.time()
        response_time = end_time - start_time
        
        result = TestResult(
            request_id=request_id,
            endpoint=endpoint,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            response_length=response_length,
            response_time=response_time,
            sensitive_info=[],
            timestamp=datetime.now(),
            error=error_msg,
        )
        
        return result
    
    def get_chain_results(self, chain_id: str) -> List[TestResult]:
        """
        获取请求链执行结果
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            TestResult 列表，如果链不存在则返回空列表
        """
        return self._chain_results.get(chain_id, [])
    
    def get_chain_statistics(self, chain_id: str) -> Dict[str, Any]:
        """
        获取请求链执行统计信息
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            统计信息字典
        """
        results = self.get_chain_results(chain_id)
        
        if not results:
            return {
                "chain_id": chain_id,
                "total_steps": 0,
                "executed_steps": 0,
                "success_count": 0,
                "failure_count": 0,
                "success_rate": 0.0,
                "total_time": 0.0,
                "average_time": 0.0,
            }
        
        total_steps = len(results)
        success_count = sum(1 for r in results if not r.error)
        failure_count = total_steps - success_count
        total_time = sum(r.response_time for r in results)
        
        return {
            "chain_id": chain_id,
            "total_steps": total_steps,
            "executed_steps": total_steps,
            "success_count": success_count,
            "failure_count": failure_count,
            "success_rate": success_count / total_steps if total_steps > 0 else 0.0,
            "total_time": total_time,
            "average_time": total_time / total_steps if total_steps > 0 else 0.0,
        }
    
    def add_chain(self, chain: RequestChain) -> None:
        """
        添加请求链
        
        Args:
            chain: RequestChain 对象
        """
        self._chains[chain.chain_id] = chain
        logger.info(f"添加请求链: {chain.name}, chain_id={chain.chain_id}")
    
    def remove_chain(self, chain_id: str) -> bool:
        """
        移除请求链
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            是否成功移除
        """
        if chain_id in self._chains:
            chain = self._chains.pop(chain_id)
            self._chain_results.pop(chain_id, None)
            logger.info(f"移除请求链: {chain.name}, chain_id={chain_id}")
            return True
        return False
    
    def get_chain(self, chain_id: str) -> Optional[RequestChain]:
        """
        获取请求链
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            RequestChain 对象，如果不存在则返回 None
        """
        return self._chains.get(chain_id)
    
    def list_chains(self) -> List[RequestChain]:
        """
        列出所有请求链
        
        Returns:
            RequestChain 列表
        """
        return list(self._chains.values())
    
    def execute_all_chains(
        self,
        http_client: HttpClient,
        stop_on_error: bool = False
    ) -> Dict[str, List[TestResult]]:
        """
        执行所有请求链
        
        Args:
            http_client: HTTP 客户端实例
            stop_on_error: 某个链失败时是否停止执行所有链，默认 False
            
        Returns:
            字典 {chain_id: List[TestResult]}
            
        Example:
            >>> executor = RequestChainExecutor()
            >>> with HttpClient() as client:
            ...     results = executor.execute_all_chains(client)
        """
        all_results: Dict[str, List[TestResult]] = {}
        
        enabled_chains = [c for c in self._chains.values() if c.enabled]
        logger.info(f"开始执行所有请求链，共 {len(enabled_chains)} 个启用的链")
        
        for chain in enabled_chains:
            try:
                results = self.execute_chain(chain, http_client, stop_on_error=True)
                all_results[chain.chain_id] = results
            except Exception as e:
                logger.error(f"请求链执行异常: {chain.name}, error={e}")
                if stop_on_error:
                    logger.warning("停止执行后续请求链")
                    break
        
        total_success = sum(
            1 for results in all_results.values()
            for r in results if not r.error
        )
        total_steps = sum(len(results) for results in all_results.values())
        
        logger.info(
            f"所有请求链执行完成: "
            f"成功={total_success}/{total_steps}, "
            f"链数={len(all_results)}"
        )
        
        return all_results
    
    def set_variable(self, name: str, value: str) -> None:
        """
        设置变量
        
        Args:
            name: 变量名
            value: 变量值
        """
        self._variable_pool[name] = value
        logger.debug(f"设置变量: {name} = {value}")
    
    def get_variable(self, name: str) -> Optional[str]:
        """
        获取变量
        
        Args:
            name: 变量名
            
        Returns:
            变量值，如果不存在则返回 None
        """
        return self._variable_pool.get(name)
    
    def get_all_variables(self) -> Dict[str, str]:
        """
        获取所有变量
        
        Returns:
            变量字典
        """
        return dict(self._variable_pool)
    
    def clear_variables(self) -> None:
        """
        清空变量池
        """
        self._variable_pool.clear()
        logger.info("变量池已清空")
    
    def enable_chain(self, chain_id: str) -> bool:
        """
        启用请求链
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            是否成功
        """
        chain = self.get_chain(chain_id)
        if chain:
            chain.enabled = True
            logger.info(f"启用请求链: {chain.name}")
            return True
        return False
    
    def disable_chain(self, chain_id: str) -> bool:
        """
        禁用请求链
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            是否成功
        """
        chain = self.get_chain(chain_id)
        if chain:
            chain.enabled = False
            logger.info(f"禁用请求链: {chain.name}")
            return True
        return False
    
    def get_step_dependencies(self, chain_id: str) -> Dict[str, List[str]]:
        """
        获取步骤依赖关系
        
        分析每个步骤提取的变量和使用的变量，构建依赖关系图。
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            字典 {step_id: [依赖的变量列表]}
        """
        chain = self.get_chain(chain_id)
        if not chain:
            return {}
        
        extracted_vars: Dict[str, str] = {}
        dependencies: Dict[str, List[str]] = {}
        
        for step in chain.steps:
            used_vars = self._find_variables_in_step(step)
            
            deps = []
            for var in used_vars:
                if var in extracted_vars:
                    deps.append(extracted_vars[var])
            
            dependencies[step.step_id] = deps
            
            for rule in step.extract_rules:
                extracted_vars[rule.variable_name] = step.step_id
        
        return dependencies
    
    def _find_variables_in_step(self, step: ChainStep) -> List[str]:
        """
        查找步骤中使用的变量
        
        Args:
            step: 步骤对象
            
        Returns:
            变量名列表
        """
        variables = set()
        
        pattern = r'\{\{(\w+)\}\}'
        
        matches = re.findall(pattern, step.endpoint.url)
        variables.update(matches)
        
        for value in step.endpoint.headers.values():
            matches = re.findall(pattern, value)
            variables.update(matches)
        
        for param in step.endpoint.parameters:
            if param.default_value:
                matches = re.findall(pattern, str(param.default_value))
                variables.update(matches)
            if param.example:
                matches = re.findall(pattern, str(param.example))
                variables.update(matches)
        
        return list(variables)
    
    def export_chain_summary(self, chain_id: str) -> Dict[str, Any]:
        """
        导出请求链摘要
        
        包含请求链基本信息、执行结果和统计信息。
        
        Args:
            chain_id: 请求链 ID
            
        Returns:
            摘要字典
        """
        chain = self.get_chain(chain_id)
        if not chain:
            return {}
        
        results = self.get_chain_results(chain_id)
        statistics = self.get_chain_statistics(chain_id)
        dependencies = self.get_step_dependencies(chain_id)
        
        steps_summary = []
        for step in chain.steps:
            step_result = next(
                (r for r in results if r.endpoint.url == step.endpoint.url),
                None
            )
            
            step_summary = {
                "step_id": step.step_id,
                "order": step.order,
                "endpoint": f"{step.endpoint.method} {step.endpoint.path}",
                "extract_rules": [
                    {"variable": r.variable_name, "source": r.source}
                    for r in step.extract_rules
                ],
                "status": "success" if step_result and not step_result.error else "failure",
                "response_time": step_result.response_time if step_result else 0,
            }
            steps_summary.append(step_summary)
        
        return {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "enabled": chain.enabled,
            "total_steps": len(chain.steps),
            "statistics": statistics,
            "dependencies": dependencies,
            "steps": steps_summary,
        }
