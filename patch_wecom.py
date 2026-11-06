"""WeCom-RC-NoQR: WeCom 5.0.13.6005 single-point compatibility experiment."""
import argparse
import array
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ORIGINAL_SHA256 = '9f7dcb2a085c9a379adbc9a3375d6d314f6cf101f2517b211f1902a261c9f242'
PATCHED_SHA256 = '182b59c26e6bb6280810af7f0fa133d79d3979b5938634e21931fc052d0ae7bd'
FILE_SIZE = 285517592
PATCH_OFFSET = 0x07FA18D4
ORIGINAL_BYTES = bytes.fromhex('0f845a010000')
PATCHED_BYTES = bytes.fromhex('e95b01000090')
CHECKSUM_OFFSET = 0x248


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def classify(data):
    digest = sha256(data)
    if digest == ORIGINAL_SHA256:
        return 'original'
    if digest == PATCHED_SHA256:
        return 'patched'
    return 'unsupported'


def ensure_closed():
    command = 'if (Get-Process -Name WXWork -ErrorAction SilentlyContinue) { exit 3 }'
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
        capture_output=True,
    )
    if result.returncode == 3:
        raise RuntimeError('请先退出企业微信，包括托盘后台进程。')
    if result.returncode != 0:
        raise RuntimeError('无法检查企业微信进程，已停止操作。')


def make_patch(original):
    if classify(original) != 'original':
        raise RuntimeError('文件哈希不符合已验证原版，已停止操作。')
    if len(original) != FILE_SIZE or original[PATCH_OFFSET:PATCH_OFFSET + 6] != ORIGINAL_BYTES:
        raise RuntimeError('文件大小或原始指令不匹配。')
    pe_offset = struct.unpack_from('<I', original, 0x3c)[0]
    if pe_offset + 24 + 64 != CHECKSUM_OFFSET or original[pe_offset:pe_offset + 4] != b'PE\0\0':
        raise RuntimeError('PE 文件头不符合预期。')
    data = bytearray(original)
    data[PATCH_OFFSET:PATCH_OFFSET + 6] = PATCHED_BYTES
    data[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 4] = b'\0' * 4
    words = array.array('H')
    words.frombytes(data)
    if sys.byteorder != 'little':
        words.byteswap()
    checksum = sum(words)
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    struct.pack_into('<I', data, CHECKSUM_OFFSET, (checksum + len(data)) & 0xffffffff)
    if sha256(data) != PATCHED_SHA256:
        raise RuntimeError('补丁输出哈希不匹配，已停止操作。')
    return data


def backup_original(path, original):
    if path.exists():
        if sha256(path.read_bytes()) != ORIGINAL_SHA256:
            raise RuntimeError('已有备份的哈希不匹配，请先保管并移走该备份。')
        return
    created = False
    try:
        with path.open('xb') as stream:
            created = True
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        if sha256(path.read_bytes()) != ORIGINAL_SHA256:
            raise RuntimeError('备份校验失败。')
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise


def replace_file(target, data, expected_current_hash):
    descriptor, name = tempfile.mkstemp(prefix='WXWork-patch-', suffix='.tmp', dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if sha256(temporary.read_bytes()) != sha256(data):
            raise RuntimeError('临时文件校验失败。')
        ensure_closed()
        if sha256(target.read_bytes()) != expected_current_hash:
            raise RuntimeError('目标文件在操作期间发生变化，已停止替换。')
        os.replace(temporary, target)
        if sha256(target.read_bytes()) != sha256(data):
            raise RuntimeError('落盘校验失败，请使用原版备份恢复。')
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description='企业微信 5.0.13.6005 单点实验补丁，含原版备份和恢复。')
    parser.add_argument('command', choices=['info', 'patch', 'restore'])
    parser.add_argument('target', help='已安装的 WXWork.exe 完整路径')
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('此工具仅支持 Windows。')
    target = Path(args.target).expanduser().resolve(strict=True)
    if not target.is_file() or target.name.lower() != 'wxwork.exe':
        raise RuntimeError('请指定 WXWork.exe 文件。')
    data = target.read_bytes()
    state = classify(data)
    print('文件', target)
    print('SHA256', sha256(data))
    print('状态', {'original': '匹配原版', 'patched': '匹配单点修改版', 'unsupported': '不支持的文件'}[state])
    if args.command == 'info':
        return 0 if state != 'unsupported' else 2
    if state == 'unsupported':
        raise RuntimeError('此文件不在已验证范围内，已停止操作。')
    backup = target.with_name(target.name + '.singlepoint-original.bak')
    if args.command == 'patch':
        if state == 'patched':
            print('已应用相同补丁。')
            return 0
        ensure_closed()
        patched = make_patch(data)
        backup_original(backup, data)
        replace_file(target, patched, ORIGINAL_SHA256)
        print('修改完成，文件哈希校验通过。')
        print('数字签名将显示 HashMismatch。请启动企业微信测试。')
    else:
        if state == 'original':
            print('当前已是匹配原版。')
            return 0
        original = backup.read_bytes()
        if sha256(original) != ORIGINAL_SHA256:
            raise RuntimeError('备份哈希不匹配，已停止恢复。')
        ensure_closed()
        replace_file(target, original, PATCHED_SHA256)
        print('恢复完成，原版哈希校验通过。')
    print('备份位置', backup)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, struct.error) as error:
        print('操作失败', error, file=sys.stderr)
        sys.exit(1)
