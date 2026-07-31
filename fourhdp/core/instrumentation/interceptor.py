"""
Identity-Aware System Interceptor for Multi-Agent Systems.

This module hooks low-level Python execution points and identifies the calling agent
by inspecting the call stack. It filters out internal library calls.
"""
import functools
import importlib
import inspect
import os
import shlex
import threading
import traceback
from typing import Callable, Dict, Optional, Tuple, List, Any

from fourhdp.core.datatypes import InterceptionContext, SecurityException

# Thread-local storage for re-entrancy guard
_audit_context = threading.local()

class SystemInterceptor:
    """
    Hooks system functions and identifies calling agents via stack inspection.
    """

    def __init__(self):
        self._original_funcs: Dict[str, Callable] = {}
        # 只要调用栈中仅包含这些包且没有经过智能体逻辑，则视为内部调用
        self.TRUSTED_INTERNAL_PACKAGES = {
            'pandas', 'numpy', 'importlib', 'json', 'yaml', 
            'pkg_resources', 'transformers', 'torch', 'typing'
        }
        # 匹配智能体类的特征词
        self._agent_patterns = ("Agent", "Role", "UserProxy", "Interpreter", "Assistant", "SystemAdminAgent")

    def _identify_caller(self) -> str:
        """
        深度分析调用栈，区分智能体行为与系统库内部行为。
        
        Returns:
            "AgentClassName:0xID" 或 "INTERNAL_BYPASS" 或 "System"
        """
        try:
            frames = inspect.stack()    # 获取当前的栈帧列表
            is_internal_lib = False

            # 从触发点（第2帧之后）向上溯源
            # Frame 0 = _identify_caller, Frame 1 = wrapper
            # Frame 2+ = 用户/Agent 代码
            for frame_info in frames[2:]:
                filename = frame_info.filename or ""
                # 跳过 FourHDP 自身代码
                if "fourhdp" in filename:
                    continue

                # 检查是否命中了受信任库的路径
                if any(f"/{pkg}/" in filename.replace("\\", "/") for pkg in self.TRUSTED_INTERNAL_PACKAGES):
                    is_internal_lib = True

                # 检查局部变量中是否存在 'self'，进而识别 Agent 实例
                frame_locals = frame_info.frame.f_locals
                if 'self' in frame_locals:
                    obj = frame_locals['self']
                    class_name = type(obj).__name__
                    
                    # 排除 FourHDP 内部类
                    if class_name in ('FourHDP', 'SystemInterceptor', 'HybridAuditor'):
                        continue
                    
                    # 匹配智能体模式
                    if any(pattern in class_name for pattern in self._agent_patterns):
                        # 发现 Agent 实例，说明这是 Agent 触发的任务
                        return f"{class_name}:{hex(id(obj))}"
                
                # 检查类方法
                if 'cls' in frame_locals:
                    cls = frame_locals['cls']
                    class_name = getattr(cls, '__name__', '')
                    if any(pattern in class_name for pattern in self._agent_patterns):
                        return f"{class_name}:class"

            # 如果整条链路中包含信任库且没有发现 Agent 实例，则判定为内部调用
            if is_internal_lib:
                return "INTERNAL_BYPASS"
                            
        except Exception:
            pass
        
        return "System"

    def _recover_source_from_code_object(self, code_obj) -> str:
        """
        尝试从 CodeObject 恢复源代码。
        策略:
        0. 从 Agent 实例的 messages 列表中提取最近生成的代码
        1. 在调用栈的局部变量中搜索源码字符串
        2. 使用 dis 模块做字节码反编译
        3. 提取 co_consts 中的字符串常量
        """
        import dis
        import io
        import types

        # 策略 0: 从 Agent 实例中提取最近生成的代码
        # Open Interpreter 的 messages 列表中包含 type='code' 的条目
        try:
            frames = inspect.stack()
            for frame_info in frames[2:]:
                f_locals = frame_info.frame.f_locals
                if 'self' in f_locals:
                    obj = f_locals['self']
                    class_name = type(obj).__name__
                    # 如果找到 Agent 实例，尝试提取 messages
                    if any(p in class_name for p in self._agent_patterns):
                        messages = getattr(obj, 'messages', None)
                        if messages and isinstance(messages, list):
                            # 从最新的 messages 中找 code 类型
                            for msg in reversed(messages):
                                if isinstance(msg, dict):
                                    # Open Interpreter message format
                                    if msg.get('type') == 'code' or msg.get('role') == 'assistant':
                                        code_content = msg.get('content', '')
                                        if code_content and isinstance(code_content, str) and len(code_content) > 5:
                                            return code_content[:2000]
        except Exception:
            pass

        # 策略 1: 在调用栈中搜索名为 'code' 等的局部变量
        # 注意: 排除 content/text 等通用变量名（容易匹配到 system prompt）
        code_var_names = ('code', 'source', 'source_code', 'code_str',
                          'python_code', 'language_code', 'code_to_run',
                          'code_block', 'script', 'preprocessed_code')
        try:
            frames = inspect.stack()
            for frame_info in frames[2:]:
                filename = frame_info.filename or ""
                # 跳过 FourHDP 自身
                if "fourhdp" in filename:
                    continue
                f_locals = frame_info.frame.f_locals
                for var_name in code_var_names:
                    if var_name in f_locals:
                        val = f_locals[var_name]
                        if isinstance(val, str) and len(val) > 5:
                            return val[:2000]
        except Exception:
            pass

        # 策略 2: 使用 dis 模块反编译字节码
        try:
            output = io.StringIO()
            dis.dis(code_obj, file=output)
            bytecode_text = output.getvalue()
            interesting_lines = []
            for line in bytecode_text.split('\n'):
                line_stripped = line.strip()
                if any(keyword in line_stripped for keyword in
                       ('LOAD_CONST', 'LOAD_NAME', 'LOAD_ATTR', 'CALL',
                        'IMPORT_NAME', 'STORE_NAME')):
                    interesting_lines.append(line_stripped)
            if interesting_lines:
                return "[Bytecode] " + "; ".join(interesting_lines[:20])
        except Exception:
            pass

        # 策略 3: 提取 co_consts 中的字符串常量
        try:
            consts = []
            for c in code_obj.co_consts:
                if isinstance(c, str) and len(c) > 5 and c not in ('__main__', '<module>'):
                    consts.append(c[:200])
                elif isinstance(c, types.CodeType):
                    consts.append(f"<func:{c.co_name}>")
            if consts:
                return "[Constants] " + " | ".join(consts[:10])
        except Exception:
            pass

        return f"<CodeObject: {getattr(code_obj, 'co_name', 'unknown')}>"

    def _extract_payload(self, module_name: str, func_name: str, args: tuple, kwargs: dict) -> Tuple[str, List[Any], Dict[str, Any]]:
        """
        从被拦截的函数参数中提取清洁的代码或命令负载。
        """
        clean_args = list(args)
        clean_kwargs = kwargs.copy()
        cleaned_payload = ""
        
        if 'env' in clean_kwargs:
            clean_kwargs['env'] = "<ENV_STRIPPED>"
        
        if func_name in ('exec', 'eval'):
            if args:
                code = args[0]
                if isinstance(code, str):
                    cleaned_payload = code[:2000]
                elif hasattr(code, 'co_code'):
                    # 尝试恢复源代码而不仅仅记录 CodeObject 名称
                    cleaned_payload = self._recover_source_from_code_object(code)
                else:
                    cleaned_payload = str(code)[:500]
                    
        elif module_name == 'os' and func_name == 'system':
            if args:
                cleaned_payload = str(args[0])[:2000]
                
        elif module_name == 'subprocess' and func_name in ('run', 'call', 'Popen'):
            if args:
                cmd = args[0]
                if isinstance(cmd, list):
                    try:
                        cleaned_payload = shlex.join(cmd)
                    except AttributeError:
                        cleaned_payload = " ".join(str(c) for c in cmd)
                elif isinstance(cmd, str):
                    cleaned_payload = cmd[:2000]
                else:
                    cleaned_payload = str(cmd)[:500]
                clean_args[0] = cleaned_payload
        else:
            if args:
                cleaned_payload = str(args[0])[:500]
        
        return cleaned_payload, clean_args, clean_kwargs

    def hook_function(self, module_name: str, func_name: str, execution_wrapper: Optional[Callable] = None):
        """
        通过 Monkey-patching 挂载钩子。
        """
        full_qual_name = f"{module_name}.{func_name}"
        module = importlib.import_module(module_name)
        # 将原始函数强行替换为防御系统自定义的拦截装饰器 wrapper 函数
        original_func = getattr(module, func_name)
        
        self._original_funcs[full_qual_name] = original_func
        
        @functools.wraps(original_func)
        def wrapper(*args, **kwargs):
            if getattr(_audit_context, 'auditing', False):
                return original_func(*args, **kwargs)
            
            # 1. Identify the caller and optionally apply Stage-1 flow screening.
            # FOURHDP_FLOW_SCREENING=0 keeps the interception hook but disables
            # trusted-internal bypass, which is useful for the reviewer-facing
            # screening ablation.  It intentionally increases audit noise.
            agent_id = self._identify_caller()
            screening_enabled = os.environ.get("FOURHDP_FLOW_SCREENING", "1").strip().lower() not in {
                "0", "false", "no", "off"
            }

            # 2. Trusted-library calls are filtered only when screening is enabled.
            if agent_id == "INTERNAL_BYPASS" and screening_enabled:
                return original_func(*args, **kwargs)
            if agent_id == "INTERNAL_BYPASS":
                agent_id = "UNFILTERED_INTERNAL"

            # 3. Enter the defense audit path.
            _audit_context.auditing = True
            try:
                cleaned_payload, clean_args, clean_kwargs = self._extract_payload(
                    module_name, func_name, args, kwargs
                )
                
                stack = "".join(traceback.format_stack()[-10:-1])
                # 结构化打包生成并实例化为一个 InterceptionContext
                ctx = InterceptionContext(
                    function_name=f"{module_name}.{func_name}",
                    module=module_name,
                    agent_id=agent_id,
                    args=clean_args,
                    kwargs=clean_kwargs,
                    stack_trace=stack,
                    cleaned_payload=cleaned_payload,
                    flow_screening_enabled=screening_enabled,
                )
                
                if execution_wrapper:
                    return execution_wrapper(ctx, original_func, *args, **kwargs)
                return original_func(*args, **kwargs)
            finally:
                _audit_context.auditing = False
        
        setattr(module, func_name, wrapper)

    def unhook_all(self):
        for qual_name, original_func in self._original_funcs.items():
            mod_name, f_name = qual_name.rsplit('.', 1)
            module = importlib.import_module(mod_name)
            setattr(module, f_name, original_func)
        self._original_funcs.clear()