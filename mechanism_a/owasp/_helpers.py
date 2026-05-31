"""案例编写共享工具：临时目录、目录切换、源码拼装。

所有 exploit 仅在临时目录内运行，危害动作仅限临时目录内（touch 标记 / 读写临时文件 /
返回布尔），绝不触碰临时目录以外的真实资源。符合 PROBLEM_AND_RQ_DESIGN.md §8。
"""

import contextlib
import os
import shutil
import tempfile


@contextlib.contextmanager
def tmp():
    d = tempfile.mkdtemp(prefix="case_")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@contextlib.contextmanager
def chdir(d):
    old = os.getcwd()
    os.chdir(d)
    try:
        yield
    finally:
        os.chdir(old)


def J(lines):
    """把代码行列表拼成源码字符串。"""
    return "\n".join(lines) + "\n"
