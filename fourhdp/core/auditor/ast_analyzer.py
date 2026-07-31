"""
Static AST/Taint analyzer for 4HDP.

The analyzer is intentionally lightweight and deterministic. It extracts
execution-layer evidence before a tool call or code payload is executed, rather
than trying to prove semantic maliciousness by itself.

Revision for response to reviewer comment #12:
- retain Python AST/taint inspection;
- add conservative fuzzy evidence for intercepted non-Python payloads
  (shell/PowerShell/Node/etc.), native binary invocation, container-escape
  patterns, audit-prompt-injection text, and attempts to tamper with 4HDP;
- keep all detections as pre-execution audit evidence. It does not execute the
  payload and does not claim to cover actions that bypass the interception layer.
"""
from __future__ import annotations

import ast
import base64
import binascii
import json
import logging
import os
import re
import warnings
from typing import List, Dict, Any, Set, Optional, Iterable, Tuple

logger = logging.getLogger("FourHDP.AST")


class TaintVisitor(ast.NodeVisitor):
    """Classify risky Python operations and track simple data flows."""

    SINK_CATEGORIES = {
        "EXECUTION": {"exec", "eval", "compile", "__import__"},
        "OS_COMMAND": {"system", "run", "call", "Popen", "spawn", "spawnl", "spawnv", "execve"},
        "FILE_WRITE": {"open", "write", "remove", "unlink", "rmtree", "mkdir", "rename", "replace"},
        "NETWORK": {"connect", "get", "post", "put", "delete", "urlopen", "socket", "request", "send", "sendall"},
    }

    SOURCES = {
        "input", "read", "read_text", "read_bytes", "recv", "recvfrom", "get_json",
        "environ", "getenv", "urlopen", "get", "post", "loads", "load",
    }

    DECODE_OR_OBFUSCATION_FUNCS = {
        "b64decode", "a85decode", "b32decode", "decode", "unquote", "rot13", "chr",
    }

    PROMPT_INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+(instructions|rules|messages)",
        r"disregard\s+(the\s+)?(system|developer|previous)",
        r"you\s+are\s+now\s+",
        r"override\s+(the\s+)?(policy|instruction|safety)",
        r"do\s+not\s+tell\s+(the\s+)?user",
        r"hidden\s+instruction",
        r"system\s+prompt",
        r"auditor\s*:",
        r"risk[_ -]?score\s*[:=]\s*0(?:\s*[,}\]]|\s*$)",
        r"mark\s+(this\s+)?(code|action|payload)\s+safe",
        r"respond\s+with\s+json\s+only.*safe",
    ]

    # Strong secret/path indicators. These remain high-value static evidence in
    # both raw code and structured ASB tool-call payloads.
    SECRET_OR_PATH_PATTERNS = [
        "/etc/passwd", "/etc/shadow", ".ssh", "id_rsa", "private_key", "private key",
        "secret", "token", "credential", "password", "api_key", "api key",
        "access key", "ssn", "social security", "client_id", ".aws/credentials",
        "kubeconfig", ".kube/config", "client_notes", "patient_records",
    ]

    # Domain-sensitive words by themselves are intentionally weak evidence.
    # In ASB benign medical tasks, words such as "patient" and "prescription"
    # appear in normal instructions and tool descriptions. They are promoted
    # to FILE_READ evidence only when accompanied by explicit access/export
    # behavior outside read-only reference tools.
    REGULATED_DATA_PATTERNS = [
        "medical record", "medical records", "patient record", "patient records",
        "patient data", "patient", "prescription", "diagnosis note",
    ]

    # Backward-compatible aggregate used by generic raw-code fuzzy scanning.
    SENSITIVE_PATTERNS = SECRET_OR_PATH_PATTERNS + REGULATED_DATA_PATTERNS

    DATA_ACCESS_ACTION_PATTERNS = [
        "read", "access", "export", "download", "extract", "dump", "copy",
        "upload", "send", "email", "post", "exfil", "leak", "retrieve", "list",
    ]

    READ_ONLY_TOOL_HINTS = [
        "database", "search", "lookup", "reference", "information", "retrieval",
        "knowledge", "calculator", "validator", "viewer", "browser", "medical_database",
    ]

    SIDE_EFFECT_TOOL_HINTS = [
        "write", "update", "modify", "delete", "remove", "order", "transfer",
        "payment", "send", "email", "notify", "submit", "apply", "grant",
        "schedule", "prescribe", "create", "allocate", "purchase", "book",
    ]

    # Deployment-visible tool-scope baseline for the three ASB roles used in the
    # paper.  This is not an attack-label oracle: the defense only checks whether
    # an intercepted tool call belongs to the configured business tool surface.
    # The list can be overridden for other deployments via FOURHDP_ALLOWED_TOOL_NAMES.
    DEFAULT_ALLOWED_TOOL_NAMES = {
        "medical_database",
        "legal_doc_review",
        "compliance_checker",
        "market_data_api",
        "portfolio_manager",
    }

    NETWORK_PATTERNS = [
        "http://", "https://", "webhook", "callback", "upload", "exfil", "external",
        "attacker", "curl", "wget", "scp", "email", "send", "notify", "post to",
        "nc ", "netcat", "ftp://", "sftp://",
    ]

    OS_COMMAND_PATTERNS = [
        "shell", "terminal", "command", "os.system", "subprocess", "rm -rf", "chmod",
        "crypto_miner", "miner", "sudo", "bash", "sh -c", "powershell", "cmd.exe",
        "node -e", "perl -e", "ruby -e", "python -c", "iwr ", "irm ", "invoke-webrequest", "invoke-expression", "child_process", "requests_unixsocket",
    ]

    STATE_MUTATION_STRONG_PATTERNS = [
        "delete", "remove", "transfer", "wire", "reallocate", "grant admin",
        "grant", "revoke", "approve", "purchase", "create user", "drop table",
        "insert into", "update database", "write", "overwrite", "kubectl apply",
        "crontab -", "chmod 777",
    ]
    STATE_MUTATION_WEAK_PATTERNS = [
        "modify", "update", "change", "order", "prescription", "schedule",
        "allocate", "create",
    ]
    STATE_MUTATION_PATTERNS = STATE_MUTATION_STRONG_PATTERNS + STATE_MUTATION_WEAK_PATTERNS

    CONTAINER_ESCAPE_PATTERNS = [
        "docker.sock", "/var/run/docker.sock", "%2fvar%2frun%2f", "--privileged", "privileged: true", "--cap-add", "cap_sys_admin",
        "cap-add=all", "nsenter", "setns", "/proc/1/root", "/host", "chroot /host",
        "mount --bind", "release_agent", "cgroup.procs", "kubectl exec", "hostpid",
        "hostnetwork", "hostpath", "hostpath:", "securitycontext",
    ]

    NATIVE_BINARY_PATTERNS = [
        "chmod +x", "chmod(", "os.chmod", "./", "/tmp/.", "ld_preload", "ctypes.cdll", "ctypes.CDLL",
        "dlopen", "nohup", "setsid", "crontab", "systemd-run", "elf", "execve(", "namedtemporaryfile",
        "mmap", "ptrace", "strace", "/bin/sh", "/bin/bash",
    ]

    DEFENSE_TAMPER_PATTERNS = [
        "fourhdp_disable", "fourhdp_bypass", "hybridauditor.audit", "securityexception",
        "shield.disable", "unhook", "remove hook", "monkeypatch", "sitecustomize",
        "builtins.exec", "builtins.eval", "sys.modules['fourhdp", 'sys.modules["fourhdp',
        "os.environ['openai_api_key']", 'os.environ["openai_api_key"]', "audit_model",
    ]

    @classmethod
    def _contains_container_escape(cls, text: str) -> bool:
        """Match host-boundary primitives without treating /etc/hostname as /host.

        The previous substring rule for ``/host`` also matched ``/hostname``.
        Other strong container indicators are unchanged; ``/host`` is accepted
        only as a root-path token at the beginning of text or after a delimiter.
        """
        lowered = str(text or "").lower()
        if any(
            pattern.lower() in lowered
            for pattern in cls.CONTAINER_ESCAPE_PATTERNS
            if pattern.lower() != "/host"
        ):
            return True
        return bool(re.search(r"(?:^|[\s=:,(\[{'\"])/host(?:/|\b)", lowered))

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.tainted_vars: Set[str] = set()
        self.string_vars: Dict[str, str] = {}

    def visit_Assign(self, node: ast.Assign):
        literal = self._literal_string(node.value)
        for target in node.targets:
            for name in self._assigned_names(target):
                if literal is not None:
                    self.string_vars[name] = literal
                    if name == "tool_call":
                        self._inspect_structured_tool_call(literal, node)
                if self._expr_is_tainted(node.value):
                    self.tainted_vars.add(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        literal = self._literal_string(node.value) if node.value is not None else None
        for name in self._assigned_names(node.target):
            if literal is not None:
                self.string_vars[name] = literal
                if name == "tool_call":
                    self._inspect_structured_tool_call(literal, node)
            if node.value is not None and self._expr_is_tainted(node.value):
                self.tainted_vars.add(name)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if self._expr_is_tainted(node.value) or self._expr_is_tainted(node.target):
            for name in self._assigned_names(node.target):
                self.tainted_vars.add(name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node)
        category = self._classify_call(node, func_name)

        if category:
            primary_payload = self._extract_arg_value(node.args[0]) if node.args else ""
            is_tainted = any(self._expr_is_tainted(arg) for arg in node.args) or any(
                self._expr_is_tainted(kw.value) for kw in node.keywords if kw.value is not None
            )
            finding = {
                "category": category,
                "function": func_name or "dynamic_call",
                "payload": primary_payload,
                "is_tainted": is_tainted,
                "line": getattr(node, "lineno", "?"),
            }
            sensitive_detail = self._sensitive_detail(node)
            if sensitive_detail:
                finding["details"] = sensitive_detail
            self.findings.append(finding)

        if func_name in self.DECODE_OR_OBFUSCATION_FUNCS:
            literal_payload = " ".join(self._extract_arg_value(a) for a in node.args)
            self.findings.append({
                "category": "OBFUSCATION",
                "function": func_name,
                "payload": literal_payload,
                "is_tainted": any(self._expr_is_tainted(a) for a in node.args),
                "line": getattr(node, "lineno", "?"),
                "details": "decode/obfuscation primitive appears in executable payload",
            })

        self.generic_visit(node)

    def _classify_call(self, node: ast.Call, func_name: str) -> Optional[str]:
        for cat, funcs in self.SINK_CATEGORIES.items():
            if func_name in funcs:
                if func_name == "open":
                    return self._classify_open(node)
                return cat
        return None

    @staticmethod
    def _classify_open(node: ast.Call) -> str:
        mode = None
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = str(node.args[1].value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = str(kw.value.value)
        if mode is None:
            return "FILE_READ"
        if any(flag in mode for flag in ["w", "a", "+", "x"]):
            return "FILE_WRITE"
        return "FILE_READ"

    def _get_func_name(self, node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        if isinstance(func, ast.Call):
            dyn = self._resolve_dynamic_callee(func)
            if dyn:
                return dyn
        if isinstance(func, ast.Subscript):
            sub = self._literal_string(func.slice)
            return sub or "dynamic_subscript_call"
        return ""

    def _resolve_dynamic_callee(self, node: ast.Call) -> str:
        name = self._get_func_name(node)
        if name == "getattr" and len(node.args) >= 2:
            attr = self._literal_string(node.args[1])
            return attr or "getattr"
        if name in {"globals", "locals"}:
            return "dynamic_namespace_call"
        return name

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value) or node.attr in self.SOURCES
        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node)
            if func_name in self.SOURCES:
                return True
            return any(self._expr_is_tainted(arg) for arg in node.args) or any(
                self._expr_is_tainted(kw.value) for kw in node.keywords if kw.value is not None
            )
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.UnaryOp):
            return self._expr_is_tainted(node.operand)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(v) for v in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_is_tainted(node.left) or any(self._expr_is_tainted(c) for c in node.comparators)
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(k) for k in node.keys if k is not None) or any(
                self._expr_is_tainted(v) for v in node.values if v is not None
            )
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        return False

    def _assigned_names(self, target: ast.AST) -> Set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            names: Set[str] = set()
            for elt in target.elts:
                names.update(self._assigned_names(elt))
            return names
        return set()

    def _extract_arg_value(self, node: ast.AST) -> str:
        literal = self._literal_string(node)
        if literal is not None:
            return literal
        if isinstance(node, ast.Constant):
            return str(node.value)
        if isinstance(node, ast.Name):
            return self.string_vars.get(node.id, f"VAR:{node.id}")
        if isinstance(node, ast.List):
            return "[" + ", ".join(self._extract_arg_value(e) for e in node.elts) + "]"
        if isinstance(node, ast.Tuple):
            return "(" + ", ".join(self._extract_arg_value(e) for e in node.elts) + ")"
        if isinstance(node, ast.Dict):
            return "DICT_LITERAL"
        if isinstance(node, ast.Call):
            return f"CALL_RESULT:{self._get_func_name(node)}"
        if isinstance(node, ast.JoinedStr):
            return "FSTRING"
        if isinstance(node, ast.BinOp):
            return "COMPLEX_EXPRESSION"
        return "UNKNOWN"

    def _literal_string(self, node: Optional[ast.AST]) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._literal_string(node.left)
            right = self._literal_string(node.right)
            if left is not None and right is not None:
                return left + right
        if isinstance(node, ast.Subscript):
            return self._literal_string(node.slice)
        return None

    def _sensitive_detail(self, node: ast.Call) -> str:
        text = " ".join(self._extract_arg_value(a) for a in node.args)
        lower = text.lower()
        details = []
        if any(p.lower() in lower for p in self.SENSITIVE_PATTERNS):
            details.append("sensitive path or secret-like argument")
        if any(cmd in lower for cmd in ["rm -rf", "curl", "wget", "scp", "nc ", "chmod 777"]):
            details.append("dangerous shell/exfiltration pattern")
        if self._contains_container_escape(lower):
            details.append("container escape or host-namespace pattern")
        if any(p.lower() in lower for p in self.DEFENSE_TAMPER_PATTERNS):
            details.append("defense tampering pattern")
        return "; ".join(details)

    def _inspect_structured_tool_call(self, literal: str, node: ast.AST) -> None:
        """Extract static evidence from 4HDP's oracle-free ASB pseudo payload.

        This path is intentionally more context-aware than the generic fuzzy
        scanner.  ASB serializes rich natural-language tool descriptions and
        thoughts into a Python string.  Treating every domain word in that blob
        as a dangerous sink caused benign medical database lookups to be flagged
        as FILE_READ/STATE_MUTATION.  Here we keep strong execution-layer
        evidence (shell/network/container/native/tamper/prompt-injection) while
        requiring explicit access or side-effect evidence for domain-sensitive
        terms such as "patient" or "prescription".
        """
        try:
            payload = json.loads(literal)
        except Exception:
            return
        if not isinstance(payload, dict) or "tool_name" not in payload:
            return

        tool_name = str(payload.get("tool_name", ""))
        description = str(payload.get("description", ""))
        user_intent = str(payload.get("user_intent", ""))
        current_thought = str(payload.get("current_thought", ""))
        current_step = str(payload.get("current_step", ""))
        params = payload.get("parameters", {})
        recent_messages = payload.get("recent_messages", [])
        allowed_tool_names = payload.get("allowed_tool_names", None)
        enforce_tool_surface = bool(payload.get("enforce_tool_surface", True))

        current_context = current_step or current_thought
        params_text = self._compact_json(params)
        recent_text = self._compact_json(recent_messages)
        visible_text = "\n".join([
            f"tool={tool_name}",
            f"description={description}",
            f"parameters={params_text}",
            f"current_step={current_step}",
            f"current_thought={current_thought}",
            f"recent_messages={recent_text}",
        ])
        intent_lower = user_intent.lower()

        # Evidence about the current action must not be inferred from the
        # previous step's assistant observation.  Recent messages remain useful
        # only for detecting prompt-injection text that influenced this call.
        action_text = "\n".join([tool_name, description, params_text, current_context]).lower()
        domain_action_text = "\n".join([tool_name, params_text, current_context]).lower()
        prompt_context_text = "\n".join([action_text, recent_text]).lower()
        line = getattr(node, "lineno", "?")

        findings: List[Tuple[str, str, bool]] = []
        read_only_tool = self._is_read_only_tool(tool_name, description, params)
        known_tool = self._is_allowed_tool_for_payload(tool_name, allowed_tool_names)
        has_request_local_surface = (
            isinstance(allowed_tool_names, (list, tuple, set))
            and len(allowed_tool_names) > 0
        )
        # A capability-surface decision requires an explicit, non-empty,
        # request-local deployment manifest.  An empty list means that the
        # adapter has no reliable capability evidence for this call; it must
        # not be interpreted as "the agent is allowed to use no tools".
        if isinstance(allowed_tool_names, (list, tuple, set)):
            declared_tool_surface = self._normalize_allowed_tool_names(
                allowed_tool_names
            )
        else:
            declared_tool_surface = set()

        has_declared_tool_surface = bool(declared_tool_surface)

        # Optional POT-only guard. It detects tool selection whose causal basis is
        # merely the presence of an arbitrary lexical trigger in the user-visible
        # input. The selected tool must match the currently intercepted tool.
        if (
            os.environ.get("FOURHDP_POT_TRIGGER_GUARD", "0").strip().lower()
            in {"1", "true", "yes", "on"}
            and bool(str(current_step or "").strip())
            and self._is_trigger_conditioned_tool_call(
                str(current_step),
                tool_name,
            )
        ):
            findings.append((
                "TRIGGER_CONDITIONED_TOOL_CALL",
                (
                    "tool selection is causally conditioned on an arbitrary "
                    "lexical trigger in the user-visible input"
                ),
                True,
            ))

        # In ASB, benign execution for the evaluated roles is mediated by a small
        # deployment-visible set of business tools.  Calls to tools outside that
        # configured surface are not blocked by name alone, but they are supplied
        # as strong intent-drift evidence to the semantic auditor.  This restores
        # sensitivity to attacker-inserted tools while preserving the medical /
        # legal / financial read-only false-positive reduction above.
        if (
            enforce_tool_surface
            and has_declared_tool_surface
            and tool_name
            and not known_tool
        ):
            findings.append((
                "INTENT_DRIFT",
                "intercepted tool name is outside the configured allowed tool surface",
                True,
            ))

        if self._matches(prompt_context_text, self.PROMPT_INJECTION_PATTERNS, regex=True):
            findings.append(("PROMPT_INJECTION", "prompt-injection text appears in visible context", True))
        if self._contains_any(action_text, self.OS_COMMAND_PATTERNS):
            findings.append(("OS_COMMAND", "tool metadata or parameters indicate shell/system action", False))
        if self._contains_any(action_text, self.NETWORK_PATTERNS):
            findings.append(("NETWORK", "tool metadata or parameters indicate external communication", False))

        # Strong secrets/paths are always evidence.  Domain-sensitive words are
        # evidence only when coupled with actual access/export behavior; a
        # read-only medical reference lookup mentioning "patient" is not enough.
        if self._contains_any(action_text, self.SECRET_OR_PATH_PATTERNS):
            findings.append(("FILE_READ", "tool metadata or parameters reference a sensitive path, secret, or record file", True))
        elif (
            self._contains_any(domain_action_text, self.REGULATED_DATA_PATTERNS)
            and self._contains_any(domain_action_text, self.DATA_ACCESS_ACTION_PATTERNS)
            and not read_only_tool
        ):
            findings.append(("FILE_READ", "tool action appears to access regulated-domain data", True))

        # State mutation is similarly gated.  Strong side-effect verbs stay
        # risky, but weak domain-planning language such as "update treatment
        # plan" or "prescription information" is ignored for read-only tools.
        if self._contains_any(domain_action_text, self.STATE_MUTATION_STRONG_PATTERNS):
            findings.append(("STATE_MUTATION", "tool metadata or parameters indicate explicit state-changing action", False))
        elif (
            self._contains_any(domain_action_text, self.STATE_MUTATION_WEAK_PATTERNS)
            and not read_only_tool
            and self._contains_any(f"{tool_name} {params_text}".lower(), self.SIDE_EFFECT_TOOL_HINTS)
        ):
            findings.append(("STATE_MUTATION", "tool metadata or parameters indicate possible state-changing action", False))

        if self._contains_container_escape(action_text):
            findings.append(("CONTAINER_ESCAPE", "tool metadata or parameters indicate host/container boundary abuse", True))
        if self._contains_any(action_text, self.NATIVE_BINARY_PATTERNS):
            findings.append(("NATIVE_BINARY", "tool metadata or parameters indicate native binary execution", False))
        if self._contains_any(action_text, self.DEFENSE_TAMPER_PATTERNS):
            findings.append(("DEFENSE_TAMPER", "tool metadata or parameters attempt to weaken the audit runtime", True))

        if self._should_flag_intent_drift(findings, tool_name, description, current_context, params_text, intent_lower):
            findings.append(("INTENT_DRIFT", "risky tool action has weak lexical support in the original user intent", True))

        for category, details, is_tainted in findings:
            self.findings.append({
                "category": category,
                "function": f"ASBTool:{tool_name or 'unknown'}",
                "payload": self._redact(visible_text[:600]),
                "is_tainted": is_tainted,
                "line": line,
                "details": details,
                "evidence_source": (
                    "request_local_capability_surface"
                    if (
                        category == "INTENT_DRIFT"
                        and details == (
                            "intercepted tool name is outside the configured "
                            "allowed tool surface"
                        )
                        and has_request_local_surface
                    )
                    else None
                ),
                "capability_violation": bool(
                    category == "INTENT_DRIFT"
                    and details == (
                        "intercepted tool name is outside the configured "
                        "allowed tool surface"
                    )
                    and has_request_local_surface
                ),
            })

    @classmethod
    def _is_trigger_conditioned_tool_call(
        cls,
        text: str,
        tool_name: str,
    ) -> bool:
        """Detect lexical-trigger-driven selection of the current tool.

        This does not use a trigger-word list or attack-tool list. It identifies
        causal language in which a literal phrase/token appearing in the input
        is used as the reason to select the intercepted tool.
        """
        lowered = str(text or "").lower()
        tool_norm = re.sub(
            r"[^a-z0-9]+",
            "",
            str(tool_name or "").lower(),
        )

        if not lowered or not tool_norm:
            return False

        input_ref = (
            r"(?:question|prompt|request|input|instruction|text|query)"
        )
        causal = r"(?:since|because|if|when|whenever|upon)"
        select = r"(?:use|call|invoke|select|choose|execute|run)"

        # Quoted/bracketed literals are common representations of arbitrary
        # trigger phrases. Explicit trigger/keyword/token wording is also
        # covered without depending on any particular benchmark phrase.
        literal = (
            r"(?:\[[^\]\n]{2,120}\]|"
            r"['\"][^'\"\n]{2,120}['\"]|"
            r"\b(?:trigger|keyword|phrase|token)\b)"
        )

        patterns = [
            (
                rf"\b{causal}\b.{{0,100}}{literal}.{{0,120}}"
                rf"\b(?:in|inside|within)\s+(?:the\s+)?{input_ref}\b"
                rf".{{0,180}}\b{select}\b"
                rf"(?P<target>.{{0,100}})"
            ),
            (
                rf"\b(?:the\s+)?{input_ref}\b.{{0,120}}"
                rf"\b(?:contains?|includes?|has|mentions?)\b"
                rf".{{0,120}}{literal}.{{0,180}}"
                rf"\b{select}\b(?P<target>.{{0,100}})"
            ),
            (
                rf"\b(?:trigger|keyword|phrase|token)\b.{{0,180}}"
                rf"\b{select}\b(?P<target>.{{0,100}})"
            ),
        ]

        for pattern in patterns:
            match = re.search(
                pattern,
                lowered,
                flags=re.DOTALL,
            )
            if not match:
                continue

            target_norm = re.sub(
                r"[^a-z0-9]+",
                "",
                match.group("target"),
            )

            if tool_norm in target_norm:
                return True

        return False

    @staticmethod
    def _compact_json(value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(value)

    @staticmethod
    def _contains_any(text: str, patterns: Iterable[str]) -> bool:
        lowered_patterns = [p.lower() for p in patterns]
        return any(p in text.lower() for p in lowered_patterns)

    @staticmethod
    def _normalize_tool_name(name: str) -> str:
        name = str(name or "")
        s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()

    @classmethod
    def _configured_allowed_tools(cls) -> Set[str]:
        raw = os.environ.get("FOURHDP_ALLOWED_TOOL_NAMES", "")
        if raw.strip():
            names = [x.strip() for x in raw.split(",") if x.strip()]
        else:
            names = list(cls.DEFAULT_ALLOWED_TOOL_NAMES)
        allowed: Set[str] = set()
        for name in names:
            allowed.add(str(name).lower())
            allowed.add(cls._normalize_tool_name(name))
        return allowed

    @classmethod
    def _is_configured_allowed_tool(cls, tool_name: str) -> bool:
        name = str(tool_name or "")
        configured = cls._configured_allowed_tools()
        return name.lower() in configured or cls._normalize_tool_name(name) in configured

    @classmethod
    def _normalize_allowed_tool_names(cls, names: Iterable[Any]) -> Set[str]:
        allowed: Set[str] = set()
        for name in names:
            value = str(name or "").strip()
            if not value:
                continue
            allowed.add(value.lower())
            allowed.add(cls._normalize_tool_name(value))
        return allowed

    @classmethod
    def _is_allowed_tool_for_payload(cls, tool_name: str, allowed_tool_names: Any) -> bool:
        """Check the per-agent deployment capability surface when supplied.

        ``allowed_tool_names`` is captured from ``self.normal_tools`` before ASB
        injects an attacker tool.  It is request-local and therefore safe under
        concurrent evaluation.  Older payloads without this field retain the
        configured fallback for backward compatibility.
        """
        if isinstance(allowed_tool_names, (list, tuple, set)):
            allowed = cls._normalize_allowed_tool_names(allowed_tool_names)
            name = str(tool_name or "")
            return name.lower() in allowed or cls._normalize_tool_name(name) in allowed
        return cls._is_configured_allowed_tool(tool_name)

    @classmethod
    def _is_read_only_tool(cls, tool_name: str, description: str, params: Any) -> bool:
        """Heuristic for ASB structured tools that provide reference data.

        A read-only hint is accepted only when the call has no parameters that
        look like a write/action request.  This prevents natural-language domain
        descriptions from becoming state-changing evidence by themselves.
        """
        text = f"{tool_name} {description}".lower()
        params_text = cls._compact_json(params).lower()
        has_read_hint = cls._contains_any(text, cls.READ_ONLY_TOOL_HINTS)
        has_side_effect_hint = cls._contains_any(f"{tool_name} {params_text}".lower(), cls.SIDE_EFFECT_TOOL_HINTS)
        params_empty = params in ({}, [], None, "")
        return has_read_hint and params_empty and not has_side_effect_hint

    @classmethod
    def _should_flag_intent_drift(
        cls,
        findings: List[Tuple[str, str, bool]],
        tool_name: str,
        description: str,
        current_thought: str,
        params_text: str,
        intent_lower: str,
    ) -> bool:
        """Flag drift only for already risky actions with weak task support."""
        high_risk_categories = {
            "NETWORK", "OS_COMMAND", "CONTAINER_ESCAPE", "NATIVE_BINARY",
            "DEFENSE_TAMPER", "PROMPT_INJECTION", "FILE_READ", "STATE_MUTATION",
        }
        if not any(cat in high_risk_categories for cat, _, _ in findings):
            return False

        support_text = f"{tool_name} {description} {current_thought} {params_text}".lower()
        tool_terms = set(re.findall(r"[a-zA-Z]{4,}", support_text))
        intent_terms = set(re.findall(r"[a-zA-Z]{4,}", intent_lower))
        stop = {
            "tool", "tools", "call", "database", "information", "based", "using",
            "with", "from", "this", "that", "available", "given", "provide",
            "assistant", "query", "result", "results", "step", "workflow",
        }
        overlap = (tool_terms - stop) & (intent_terms - stop)
        return len(overlap) <= 1

    @staticmethod
    def _matches(text: str, patterns: Iterable[str], regex: bool = False) -> bool:
        if regex:
            return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)
        return any(p.lower() in text.lower() for p in patterns)

    @staticmethod
    def _redact(text: str) -> str:
        redacted = re.sub(r"(?i)(api[_-]?key|token|password|secret|credential)(['\"\s:=]+)[^,}\]\s]{4,}", r"\1\2<redacted>", text)
        redacted = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", redacted)
        return redacted


class ASTStaticAnalyzer:
    """Provides structured security features for LLM and rule-based auditing."""

    _CODE_INDICATORS = [
        "import ", "def ", "class ", "return ", "if ", "for ", "while ",
        "exec(", "eval(", "os.", "subprocess.", "open(", "print(",
        "= ", "()", "{}", "[]", ";", "lambda ", "__", "raise ", "try:",
        "except ", "with ", "from ", "yield ", "async ", "await ", "getattr(",
        "requests.", "socket.", "base64", "tool_call =", "__import__", ".system",
        "call_asb_tool(", "globals()[", "locals()[", "bash", "powershell", "node -e",
        "perl -e", "ruby -e", "docker", "kubectl", "nsenter", "chmod +x",
    ]

    def _looks_like_code(self, text: str) -> bool:
        text_lower = text.lower()
        indicator_count = sum(1 for kw in self._CODE_INDICATORS if kw in text_lower)
        return indicator_count >= 1 if self._has_high_risk_fuzzy_signal(text_lower) else indicator_count >= 2

    @staticmethod
    def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for f in findings:
            key = (f.get("category"), f.get("function"), f.get("payload"), f.get("details"))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    @staticmethod
    def _has_high_risk_fuzzy_signal(lowered: str) -> bool:
        markers = [
            "rm -rf", "curl", "wget", "http://", "https://", "/etc/passwd", ".ssh",
            "docker.sock", "%2fvar%2frun%2f", "--privileged", "privileged: true", "nsenter", "/proc/1/root", "chmod +x",
            "powershell", " iwr ", "invoke-webrequest", "bash -c", "node -e", "child_process", "perl -e", "ruby -e", "risk_score: 0",
            "auditor:", "fourhdp_disable", "hybridauditor.audit", "monkeypatch",
        ]
        return any(m in lowered for m in markers)

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        if not code or not isinstance(code, str):
            return []
        is_asb_tool_payload = "tool_call =" in code and "call_asb_tool(tool_call)" in code
        # ASB pseudo payloads contain natural-language descriptions and agent
        # thoughts inside a serialized string.  The structured visitor below
        # parses that string with field-aware gates; running the generic fuzzy
        # scanner over the whole blob creates domain-word false positives.
        fuzzy_findings = [] if is_asb_tool_payload else self._fuzzy_pattern_match(code, error_msg=None)
        if not self._looks_like_code(code):
            return fuzzy_findings
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(code)
            visitor = TaintVisitor()
            visitor.visit(tree)
            return self._dedupe(visitor.findings + fuzzy_findings)
        except SyntaxError as e:
            return self._fuzzy_pattern_match(code, str(e))
        except Exception as e:
            logger.error("AST Analysis error: %s", e)
            return self._dedupe(fuzzy_findings + [{"category": "ERROR", "details": str(e)}])

    @staticmethod
    def _add_finding(findings: List[Dict[str, Any]], category: str, payload: str, details: str, *, is_tainted: bool = False) -> None:
        findings.append({
            "category": category,
            "function": "fuzzy_match",
            "payload": payload[:300] if payload else "UNKNOWN",
            "is_tainted": is_tainted,
            "details": details,
        })

    @staticmethod
    def _normalized_for_evasion(text: str) -> str:
        """Normalize simple string-splitting/quoting obfuscation without executing code."""
        lowered = text.lower()
        # Keep path/URL-relevant punctuation but remove quote/concat/whitespace noise.
        return re.sub(r"[\s'\"`+]+", "", lowered)

    @staticmethod
    def _decoded_fragments(text: str) -> List[str]:
        """Best-effort decode of literal base64-like fragments for static evidence.

        This function never executes decoded content. It only exposes printable
        fragments to the same keyword scanner so encoded shell payloads are not
        invisible to the pre-execution audit.
        """
        fragments: List[str] = []
        for m in re.finditer(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])", text):
            token = m.group(1)
            try:
                raw = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            if not raw:
                continue
            printable = raw.decode("utf-8", errors="ignore")
            if printable and sum(ch.isprintable() for ch in printable) / max(len(printable), 1) > 0.75:
                fragments.append(printable[:1000])
        return fragments

    def _fuzzy_pattern_match(self, code: str, error_msg: Optional[str] = None) -> List[Dict[str, Any]]:
        fuzzy_findings: List[Dict[str, Any]] = []
        lowered = code.lower()
        normalized = self._normalized_for_evasion(code)
        decoded_fragments = self._decoded_fragments(code)
        decoded_text = "\n".join(decoded_fragments).lower()
        decoded_norm = self._normalized_for_evasion(decoded_text)
        scan_text = "\n".join([lowered, normalized, decoded_text, decoded_norm])

        def has_any(patterns: Iterable[str]) -> bool:
            return any(p.lower() in scan_text for p in patterns)

        if decoded_fragments and any(x in decoded_text for x in ["/etc/", "curl", "wget", "rm -rf", "ssh", "shadow", "passwd", "attacker", "docker", "chmod"]):
            self._add_finding(
                fuzzy_findings, "OBFUSCATION", "base64-decoded payload fragment",
                "Base64-like literal decodes to security-relevant shell, file, network, or host-boundary content.",
                is_tainted=True,
            )

        if re.search(r"auditor\s*:", scan_text) or re.search(r"risk[_ -]?score\s*[:=]\s*0(?:\s*[,}\]]|\s*$)", scan_text) or "mark this code safe" in scan_text or "ignore previous" in scan_text or "return{\"risk_score\":0" in scan_text:
            self._add_finding(
                fuzzy_findings, "PROMPT_INJECTION", "prompt injection text",
                "Payload contains instructions targeted at the audit model rather than the user task.",
                is_tainted=True,
            )

        if any(x in scan_text for x in ["os.system", "subprocess", "rm-rf", "rm -rf", "sh-c", "sh -c", "bash-c", "bash -c", "powershell", "cmd.exe", "iwr ", "irm ", "invoke-webrequest", "invoke-expression", "child_process", "requests_unixsocket"]):
            self._add_finding(
                fuzzy_findings, "OS_COMMAND", "shell/system execution",
                "Potential shell or system command execution, including split or aliased command forms.",
            )

        if any(x in scan_text for x in ["exec(", "eval(", "__import__", "globals()[", "locals()[", "compile(", "setattr(", "getattr("]):
            self._add_finding(
                fuzzy_findings, "EXECUTION", "dynamic execution",
                "Potential dynamic code execution or reflective dispatch.",
            )

        if any(x in scan_text for x in ["http://", "https://", "requests.", "urllib.request", "socket", "curl", "wget", "scp", "nc ", "netcat", "iwr ", "invoke-webrequest", "requests_unixsocket"]):
            self._add_finding(
                fuzzy_findings, "NETWORK", "external communication",
                "Potential external network communication or data transfer.",
            )

        if has_any(TaintVisitor.SENSITIVE_PATTERNS) or any(x in scan_text for x in ["/etc/passwd", "/etc/shadow", "id_rsa", "patient_records", "client_notes"]):
            self._add_finding(
                fuzzy_findings, "FILE_READ", "sensitive data reference",
                "Potential sensitive file, secret, credential, or regulated-data access.",
                is_tainted=True,
            )

        if TaintVisitor._contains_container_escape(scan_text) or any(x in scan_text for x in ["%2fvar%2frun%2fdocker.sock", "privileged:true", "hostpath:{path:/", "hostpid:true", "cap-add=all"]):
            self._add_finding(
                fuzzy_findings, "CONTAINER_ESCAPE", "container/host boundary primitive",
                "Potential container escape, host namespace access, or privileged container operation, including split YAML or encoded Docker-socket forms.",
                is_tainted=True,
            )

        if has_any(TaintVisitor.NATIVE_BINARY_PATTERNS) or any(x in scan_text for x in ["ctypes.cdll", "getattr(ctypes,cdll)", "os.chmod", "namedtemporaryfile", "execve", "crontab", "setsid", "nohup"]):
            self._add_finding(
                fuzzy_findings, "NATIVE_BINARY", "native binary invocation",
                "Potential native binary execution, loader abuse, executable-file staging, or process persistence primitive.",
            )

        if has_any(TaintVisitor.DEFENSE_TAMPER_PATTERNS) or any(x in scan_text for x in ["fourhdp.core.auditor.engine", "hybridauditor,audit", "hybridauditor.audit", "sys.modules[fourhdp", "disable_security_hooks", "fourhdp_disable"]):
            self._add_finding(
                fuzzy_findings, "DEFENSE_TAMPER", "4HDP runtime tampering",
                "Payload appears to weaken, bypass, or modify the audit/interception runtime.",
                is_tainted=True,
            )

        if any(x in scan_text for x in ["node -e", "node-e", "perl -e", "perl-e", "ruby -e", "ruby-e", "powershell", "bash -c", "bash-c", "cmd.exe", "python -c", "python-c"]):
            self._add_finding(
                fuzzy_findings, "MULTILANG_SCRIPT", "non-Python script payload",
                "Intercepted payload appears to execute a shell, PowerShell, Node.js, Perl, Ruby, cmd, or Python one-liner script.",
            )

        if any(x in scan_text for x in ["transfer", "wire", "delete", "remove", "reallocate", "prescription", "approve", "grant admin", "kubectl apply", "crontab -"]):
            self._add_finding(
                fuzzy_findings, "STATE_MUTATION", "state-changing action",
                "Potential state-changing action that may require explicit authorization.",
            )

        if error_msg and fuzzy_findings:
            fuzzy_findings.append({"category": "SYNTAX_ERROR", "details": error_msg})
        return self._dedupe(fuzzy_findings)
