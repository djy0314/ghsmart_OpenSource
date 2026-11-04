#!/usr/bin/env python3
"""ghsmart 正式发版构建脚本：混淆 + 自校验 + 打包，一条命令到底。

用法（在项目根目录）:
    py tools/build_release.py 1.0.6

流程（每步都有断言，任何一步不过立即停止）:
  1. 前置检查: manifest 必须是 requireAdministrator（防止上次调试残留 asInvoker）、
     garble-lit 包装器存在、前端版本号与本版本一致
  2. wails build -compiler garble-lit -tags selfcheck -trimpath
  3. PE 断言: .rsrc 资源段必须存在（丢了 manifest=丢 UAC 提权=功能废）
  4. 回填自校验戳（校验域置零哈希）+ 回读自证
  5. 字符串加密抽查（关键标识不得为明文）
  6. 组包 exe + README.txt -> ghsmart_v<ver>.zip，输出 SHA256
"""
import hashlib
import os
import struct
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOROOT = r"D://tools//go126"


def die(msg):
    print("STOP: " + msg)
    sys.exit(1)


def step(n, msg):
    print("\n[%d] %s" % (n, msg), flush=True)


def main():
    ver = sys.argv[1] if len(sys.argv) > 1 else ""
    if not ver:
        die("usage: py tools/build_release.py <version>  e.g. 1.0.6")
    tag = "v" + ver
    exe_path = os.path.join(ROOT, "build", "bin", "ghsmart.exe")
    zip_path = os.path.join(ROOT, "ghsmart_%s.zip" % tag)
    readme_txt = os.path.join(ROOT, "ghsmart_release", "README.txt")

    env = dict(os.environ)
    env["GOROOT"] = GOROOT
    gobin = os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin")
    env["PATH"] = (os.path.join(GOROOT, "bin") + os.pathsep + gobin + os.pathsep
                   + env.get("PATH", ""))
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(k, None)
    wails_exe = os.path.join(gobin, "wails.exe")
    if not os.path.isfile(wails_exe):
        wails_exe = "wails"

    step(1, "前置检查")
    manifest = open(os.path.join(ROOT, "build", "windows", "wails.exe.manifest"),
                    encoding="utf-8").read()
    if 'level="requireAdministrator"' not in manifest:
        die("manifest 不是 requireAdministrator——上次调试可能残留 asInvoker，禁止发版")
    print("  manifest: requireAdministrator OK")
    wrapper = os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin", "garble-lit.bat")
    if not os.path.isfile(wrapper):
        die("找不到混淆包装器 %s" % wrapper)
    print("  garble-lit.bat: OK")
    idx = open(os.path.join(ROOT, "frontend", "dist", "index.html"), encoding="utf-8").read()
    if tag not in idx:
        die("前端 dist 里没有版本号 %s，请先更新 frontend/dist/index.html" % tag)
    print("  前端版本号: %s OK" % tag)

    step(2, "wails build（garble 混淆 + selfcheck 标签）")
    cmd = [wails_exe, "build", "-compiler", "garble-lit", "-tags", "selfcheck",
           "-trimpath", "-m", "-skipbindings"]
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    out = r.stdout + r.stderr
    if r.returncode != 0 or not os.path.isfile(exe_path):
        print(out[-2000:])
        die("wails build 失败")
    m = [l for l in out.splitlines() if "Built" in l]
    print("  " + (m[0].strip() if m else "built"))

    step(3, "PE 断言（.rsrc 必须在，丢 manifest=功能废）")
    d = open(exe_path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    coff = e + 4
    nsec = struct.unpack_from("<H", d, coff + 2)[0]
    optsz = struct.unpack_from("<H", d, coff + 16)[0]
    sect = coff + 20 + optsz
    secs = [d[sect + i * 40: sect + i * 40 + 8].rstrip(b"\0").decode("latin1")
            for i in range(nsec)]
    if ".rsrc" not in secs:
        die("产物缺少 .rsrc 段（manifest/图标丢失）")
    print("  段: %s" % ",".join(secs))
    print("  大小: %.1f MB" % (len(d) / 1048576.0))

    step(4, "字符串加密抽查")
    probes = {"alidns": 0, "GHSMART-SELFHASH": 0}
    bad = []
    for s in probes:
        if s.encode() in d:
            bad.append(s)
    if bad:
        die("关键字符串仍为明文: %s" % bad)
    print("  关键标识均已加密 OK")

    step(5, "回填自校验戳")
    stamp_py = os.path.join(ROOT, "tools", "patch_selfstamp.py")
    r = subprocess.run([sys.executable, stamp_py, exe_path], capture_output=True, text=True)
    print("  " + (r.stdout or r.stderr).strip().replace("\n", "\n  "))
    if r.returncode != 0:
        die("回填失败")
    r = subprocess.run([sys.executable, stamp_py, "--check", exe_path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die("回填后校验失败")
    print("  " + r.stdout.strip())

    step(6, "组包")
    os.makedirs(os.path.dirname(readme_txt), exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.write(exe_path, "ghsmart.exe")
        z.write(readme_txt, "README.txt")

    def sha(p):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        return h.hexdigest().upper()

    with zipfile.ZipFile(zip_path) as z:
        inner = hashlib.sha256(z.read("ghsmart.exe")).hexdigest().upper()
    zs, es = sha(zip_path), sha(exe_path)
    print("  %s  %d B" % (os.path.basename(zip_path), os.path.getsize(zip_path)))
    print("  zip SHA256: %s" % zs)
    print("  exe SHA256: %s" % es)
    if inner != es:
        die("包内 exe 与外部不一致")
    print("  包内一致性: OK")
    print("\n完成。下一步: git 提交 + GitHub Release + 官网同步。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
