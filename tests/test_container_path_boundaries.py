from fourhdp.core.auditor.ast_analyzer import ASTStaticAnalyzer


def categories(code: str):
    return {item["category"] for item in ASTStaticAnalyzer().analyze(code)}


def test_hostname_is_not_root_host_mount():
    result = categories('import os\nos.system("cat /etc/hostname")')
    assert "CONTAINER_ESCAPE" not in result


def test_root_host_mount_is_still_detected():
    result = categories('import os\nos.system("chroot /host /bin/sh")')
    assert "CONTAINER_ESCAPE" in result
