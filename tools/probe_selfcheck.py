#!/usr/bin/env python3
"""启动自校验的攻击模拟验收（对应加固规范第五节验收矩阵 1、2 条）。

不依赖 GUI / UAC：用 cmd/selfcheckprobe 这个控制台靶子，它的 Verify() 与正式程序
完全同源，只是把 MessageBox 换成 stdout，因此可以被脚本自动判定。

用例：
  A 未回填           -> 必须拒绝（VERIFY FAIL / 退出码 3）
  B 正确回填         -> 必须放行（VERIFY OK / 退出码 0）
  C 正文改 1 字节    -> 必须拒绝
  D 哈希域改 1 字节  -> 必须拒绝
  E 截断 1 字节      -> 必须拒绝
  F 尾部追加 1 字节  -> 必须拒绝
  G 幂等             -> 二次回填不改变文件
"""
import hashlib
import os
import shutil
import subprocess
import sys
import time
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAGIC = b"GHSMART-SELFHASH-STAMP-v1-000000"
HASH_LEN = 32

results = []


def run(exe):
    p = subprocess.run([exe], capture_output=True, timeout=30)
    out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
    return p.returncode, out


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  " + detail) if detail else ""))


def main():
    probe_src = os.path.join(ROOT, "cmd", "selfcheckprobe")
    work = tempfile.mkdtemp(prefix="ghsmart_selfcheck_")
    base = os.path.join(work, "probe.exe")

    env = dict(os.environ)
    env.setdefault("GOROOT", r"D://tools//go126")
    env["PATH"] = r"D://tools//go126//bin;" + env.get("PATH", "")
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(k, None)

    print("== 编译验证靶子（-tags selfcheck）==")
    build = subprocess.run(
        ["go", "build", "-tags", "selfcheck", "-o", base, "./cmd/selfcheckprobe"],
        cwd=ROOT, env=env, capture_output=True,
    )
    if build.returncode != 0:
        print(build.stderr.decode("utf-8", "replace")[:800])
        return 1
    print("  靶子: %s (%d bytes)" % (base, os.path.getsize(base)))

    stamp_py = os.path.join(ROOT, "tools", "patch_selfstamp.py")

    def stamp(path, tries=4):
        """回填自校验戳，带重试。

        Windows 上刚被 run() 执行过的 exe，其文件句柄可能晚几百毫秒才释放，
        此时 patch 的 open('wb') 会抛 PermissionError。这不是产品缺陷，
        也不该让验收假失败——所以显式重试，并把最后一次的 stderr 带出来。
        """
        last = None
        for i in range(tries):
            r = subprocess.run([sys.executable, stamp_py, path], capture_output=True)
            if r.returncode == 0:
                return r
            last = r
            time.sleep(0.25 * (i + 1))
        return last

    # A 未回填
    code, out = run(base)
    check("A 未回填 -> 拒绝", code == 3 and "VERIFY FAIL" in out, "code=%d %s" % (code, out[:60]))

    # B 正确回填
    r = stamp(base)
    stamped_ok = r.returncode == 0
    code, out = run(base)
    check("B 正确回填 -> 放行", stamped_ok and code == 0 and "VERIFY OK" in out,
          "code=%d stamp_rc=%d %s %s" % (code, r.returncode, out[:50],
                                         r.stderr.decode("utf-8", "replace")[:120]))

    # 二次回填幂等
    before = open(base, "rb").read()
    r2 = stamp(base)
    after = open(base, "rb").read()
    check("G 二次回填幂等", r2.returncode == 0 and before == after,
          "rc=%d size %d->%d" % (r2.returncode, len(before), len(after)))

    def mutant(label, fname, mutate, expect_fail=True):
        # 文件名必须纯 ASCII：Windows 不接受中文名里的尖括号等字符
        p = os.path.join(work, fname + ".exe")
        data = bytearray(open(base, "rb").read())
        data = mutate(data)
        open(p, "wb").write(bytes(data))
        code, out = run(p)
        ok = (code == 3) if expect_fail else (code == 0)
        check(label, ok, "code=%d %s" % (code, out[:60]))

    # C 正文改 1 字节
    mutant("C 正文改1字节 -> 拒绝", "mut_body", lambda d: _flip(d, 1024))
    # D 哈希域改 1 字节
    mutant("D 哈希域改1字节 -> 拒绝", "mut_hash", lambda d: _flip(d, len(d) - 1))
    # E 截断 1 字节
    mutant("E 截断1字节 -> 拒绝", "mut_trunc", lambda d: d[:-1])
    # F 尾部追加
    mutant("F 尾部追加1字节 -> 拒绝", "mut_append", lambda d: bytes(d) + b"\x00")

    shutil.rmtree(work, ignore_errors=True)

    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    print("")
    print("结果: %d/%d 通过" % (passed, total))
    return 0 if passed == total else 2


def _flip(d, pos):
    d[pos] ^= 0xFF
    return d


if __name__ == "__main__":
    sys.exit(main())
