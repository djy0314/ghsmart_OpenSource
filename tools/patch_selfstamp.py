#!/usr/bin/env python3
"""回填 ghsmart 启动自校验戳（校验域置零哈希）。

戳布局（追加在 exe 文件末尾，共 64 字节）：
    [0:32]  魔数  GHSMART-SELFHASH-STAMP-v1-0000000
    [32:64] 预期哈希 = SHA256( 文件[0:-32] || 32 个零字节 )

为什么是「置零」而不是「全文件哈希」：如果常量写的是整文件哈希，回填这个动作本身
就改变了文件，哈希立刻失效，形成死循环。把哈希域当全零参与计算，回填前后结果一致。

用法：
    py tools/patch_selfstamp.py <exe>           回填（幂等：已正确则不重复写）
    py tools/patch_selfstamp.py --check <exe>   只校验，不改文件
    py tools/patch_selfstamp.py --force <exe>   哈希不符时强制重算（仅限确认过的重建）
"""
import hashlib
import os
import sys

MAGIC = b"GHSMART-SELFHASH-STAMP-v1-000000"
HASH_LEN = 32
STAMP_LEN = 64

assert len(MAGIC) == 32, "magic must be 32 bytes, got %d" % len(MAGIC)


def compute(data: bytes) -> bytes:
    """SHA256 with the hash field zeroed. data must already include the 64B stamp."""
    h = hashlib.sha256()
    h.update(data[: len(data) - HASH_LEN])
    h.update(b"\x00" * HASH_LEN)
    return h.digest()


def has_magic(data: bytes) -> bool:
    if len(data) < STAMP_LEN:
        return False
    start = len(data) - STAMP_LEN
    return data[start:start + 32] == MAGIC


def verify(data: bytes):
    """returns (ok, existing_hex_or_None, computed_hex_or_None)"""
    if not has_magic(data):
        return False, None, None
    existing = data[-HASH_LEN:]
    expect = compute(data)
    return existing == expect, existing.hex().upper(), expect.hex().upper()


def main() -> int:
    argv = sys.argv[1:]
    mode = "patch"
    if argv and argv[0] in ("--check", "--force"):
        mode = argv[0].lstrip("-")
        argv = argv[1:]
    if len(argv) != 1:
        print(__doc__)
        return 1

    path = argv[0]
    if not os.path.isfile(path):
        print("file not found: %s" % path)
        return 1

    with open(path, "rb") as f:
        data = f.read()
    size_in = len(data)

    if mode == "check":
        if not has_magic(data):
            print("NOT STAMPED: no stamp in last 64 bytes (%d bytes)" % size_in)
            return 2
        ok, existing, expect = verify(data)
        if ok:
            print("OK: %d bytes, sha256(zeroed)=%s" % (size_in, expect))
            return 0
        print("FAIL: expected %s, found %s" % (expect, existing))
        return 3

    if not has_magic(data):
        data = data + MAGIC + b"\x00" * HASH_LEN
        print("first stamp: appended %d bytes" % STAMP_LEN)
    else:
        ok, existing, expect = verify(data)
        if ok and mode != "force":
            print("already stamped and valid, nothing to do (%d bytes)" % size_in)
            return 0
        if not ok and mode != "force":
            print("REFUSED: stamp present but hash mismatch (found %s)" % (existing or "empty"))
            print("  file changed after stamping; use --force if you really mean it")
            return 4
        print("force recompute: clearing old hash")

    digest = compute(data)
    out = data[: len(data) - HASH_LEN] + digest
    with open(path, "wb") as f:
        f.write(out)

    with open(path, "rb") as f:
        reread = f.read()
    ok, _, expect = verify(reread)
    if not ok:
        print("FAILED: reread did not verify")
        return 5

    print("stamped: %d -> %d bytes" % (size_in, len(reread)))
    print("sha256(zeroed)=%s" % expect)
    return 0


if __name__ == "__main__":
    sys.exit(main())
