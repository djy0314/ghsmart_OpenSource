# -*- coding: utf-8 -*-
"""ghsmart GUI 实机探针：验证混淆后 Wails 绑定是否仍然存活。

混淆（garble -literals -tiny）会重命名标识符。Wails 用 reflect.MethodByName 调用
前端 bindings，一旦方法名被改，界面能出来但按钮全点不动——这是最隐蔽的失败模式，
必须真启动、真截图、真看渲染进程，不能只看进程活着。

用法: py tools/probe_gui.py [exe路径]
产物: D:/workBuddy/_gui_probe.png
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

EXE = sys.argv[1] if len(sys.argv) > 1 else r"D://project//ghsmart//build//bin//ghsmart_probe.exe"
TITLE = "ghsmart - GitHub 智能加速"
PNG = r"D://workBuddy//_gui_probe.png"

u32 = ctypes.windll.user32
g32 = ctypes.windll.gdi32
k32 = ctypes.windll.kernel32
FAILS = []


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32),
                ("biHeight", ctypes.c_int32), ("biPlanes", ctypes.c_uint16),
                ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32), ("biXPelsPerMeter", ctypes.c_int32),
                ("biYPelsPerMeter", ctypes.c_int32), ("biClrUsed", ctypes.c_uint32),
                ("biClrImportant", ctypes.c_uint32)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", wt.WCHAR * 260)]


def check(name, cond, detail=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + name
          + (("  <-- " + str(detail)) if detail and not cond else ""), flush=True)
    if not cond:
        FAILS.append(name)


def windows_of_pid(pid):
    found = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(h, l):
        p = wt.DWORD()
        u32.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value != pid or not u32.IsWindowVisible(h):
            return True
        n = u32.GetWindowTextLengthW(h)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 2)
        u32.GetWindowTextW(h, buf, n + 2)
        found.append((h, buf.value))
        return True

    u32.EnumWindows(cb, 0)
    return found


def wait_window(pid, title, timeout=45):
    end = time.time() + timeout
    while time.time() < end:
        for h, t in windows_of_pid(pid):
            if t == title:
                return h
        time.sleep(0.3)
    return 0


def snapshot(hwnd, png):
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    from PIL import Image

    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

    r = RECT()
    u32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    hdc = u32.GetWindowDC(hwnd)
    mem = g32.CreateCompatibleDC(hdc)
    bmp = g32.CreateCompatibleBitmap(hdc, w, h)
    g32.SelectObject(mem, bmp)
    if not u32.PrintWindow(hwnd, mem, 2):
        u32.PrintWindow(hwnd, mem, 0)
    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth, bmi.biHeight = w, -h
    bmi.biPlanes, bmi.biBitCount, bmi.biCompression = 1, 32, 0
    buf = ctypes.create_string_buffer(w * h * 4)
    g32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bmi), 0)
    g32.DeleteObject(bmp)
    g32.DeleteDC(mem)
    u32.ReleaseDC(hwnd, hdc)
    Image.frombuffer("RGB", (w, h), buf.raw, "raw", "BGRX", 0, 1).save(png)
    print("  截图: %s %dx%d" % (png, w, h), flush=True)
    return w, h


def child_names(pid):
    """用 CreateToolhelp32Snapshot 枚举直接子进程（不依赖外部命令）。"""
    TH32CS_SNAPPROCESS = 0x00000002
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1):
        return out
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    ok = k32.Process32FirstW(snap, ctypes.byref(entry))
    while ok:
        if entry.th32ParentProcessID == pid:
            out.append(entry.szExeFile)
        ok = k32.Process32NextW(snap, ctypes.byref(entry))
    k32.CloseHandle(snap)
    return out


def main():
    subprocess.run(["taskkill", "/F", "/IM", os.path.basename(EXE)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    print("== 启动 %s ==" % EXE)
    p = subprocess.Popen([EXE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("  PID:", p.pid)

    hwnd = wait_window(p.pid, TITLE, timeout=45)
    check("进程存活", p.poll() is None, "exit=%s" % p.poll())
    check("主窗口出现（标题精确匹配）", hwnd != 0, hwnd)

    if hwnd:
        w, h = snapshot(hwnd, PNG)
        check("窗口尺寸合理", w > 400 and h > 500, "%dx%d" % (w, h))
        time.sleep(2.0)
        kids = child_names(p.pid)
        joined = ",".join(kids).lower()
        check("WebView2 渲染进程已启动（前端真加载）",
              "msedgewebview2" in joined, ",".join(kids)[:120])

    try:
        p.terminate()
        p.wait(timeout=8)
    except Exception:
        subprocess.run(["taskkill", "/F", "/PID", str(p.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("")
    print("结果: %s" % ("全部通过" if not FAILS else ("失败 %d 项: %s" % (len(FAILS), FAILS))))
    return 0 if not FAILS else 2


if __name__ == "__main__":
    sys.exit(main())
