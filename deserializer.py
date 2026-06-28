"""
本脚本用于解析 https://github.com/northpolesec/santa 生成的 spool 日志文件
将其中的 Protobuf 二进制数据转换为 Python dict，方便后续分析和统计

参考实现：Source/santactl/Commands/SNTCommandPrintLog.mm
"""
import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, "proto"))

import struct
from pathlib import Path

from google.protobuf.json_format import MessageToDict

from proto.Source.common import santa_pb2


# ─── 文件头 Magic Number 常量 ───────────────────────────────────────────────

# "SNT!" 的 ASCII 码，小端序存储为 0x21544E53。
STREAM_BATCHER_MAGIC = 0x21544E53

# Gzip 压缩文件的前两字节是 0x1F 0x8B，用小端 uint32 读取时低 16 位为 0x8B1F。
GZIP_MAGIC = 0x8B1F

# Zstd 压缩文件的前四字节是 0x28 0xB5 0x2F 0xFD，小端读取为 0xFD2FB528。
ZSTD_MAGIC = 0xFD2FB528


# ─── 解压函数 ────────────────────────────────────────────────────────────────
def decompress_gzip(data: bytes) -> bytes:
    import gzip
    return gzip.decompress(data)


def decompress_zstd(data: bytes) -> bytes:
    import zstandard as zstd
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(data, max_output_size=250 * 1024 * 1024)


"""
─── Varint 解码 (Stream Batcher) ────────────────────────────────────────────

Protobuf 用 varint 编码整数，原理：
  - 每个字节的低 7 位存数据，最高位（bit7）=1 表示"后面还有字节"，=0 表示"结束"
  - 多个字节的 7 位数据从低位到高位拼接成完整整数

举例：数字 300 = 二进制 100101100
  编码为 [0xAC, 0x02]:
    0xAC = 10101100 → 最高位1(继续), 低7位=0101100 (十进制44)
    0x02 = 00000010 → 最高位0(结束), 低7位=0000010 (十进制2)
    还原: 44 | (2 << 7) = 44 + 256 = 300

https://github.com/northpolesec/santa/blob/main/Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h
"""
def read_varint32(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        # 取低 7 位数据，左移 shift 位后合并到结果
        result |= (b & 0x7F) << shift
        # 最高位为 0 说明这是最后一个字节
        if not (b & 0x80):
            return result, offset
        shift += 7
    raise ValueError("Truncated varint")

"""
─── Stream 格式解析 ─────────────────────────────────────────────────────────

Stream 格式是新版 FSSpool 的写入格式，文件里逐条存储记录。

每条记录的二进制布局
  ┌──────────────┬──────────────┬──────────────────┬──────────────────────┐
  │ magic (4B)   │ hash (8B)    │ length (varint)  │ SantaMessage (N B)   │
  └──────────────┴──────────────┴──────────────────┴──────────────────────┘
  
对应的读取代码: SNTCommandPrintLog.mm-ReadFromStream()
"""
def parse_stream_records(data: bytes) -> list[dict]:
    """解析 Stream 格式数据。循环读取每条记录，返回 dict 列表。"""
    records = []
    offset = 0

    while offset < len(data):
        # 剩余不足 4 字节，无法读 magic，结束
        if offset + 4 > len(data):
            break

        # 读 magic number（4字节小端 uint32），校验是否为 "SNT!"
        magic = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if magic != STREAM_BATCHER_MAGIC:
            raise ValueError(f"Invalid magic 0x{magic:08X} at offset {offset - 4}")

        # 跳过 xxhash64 校验值（8字节原始字节）
        offset += 8

        # 解码 varint32 得到后面消息的字节长度，这个值就是后面 SantaMessage protobuf 序列化数据的精确大小
        msg_len, offset = read_varint32(data, offset)

        # 按长度截取 protobuf 序列化字节
        msg_bytes = data[offset:offset + msg_len]
        offset += msg_len

        # 反序列化
        msg = santa_pb2.SantaMessage()
        msg.ParseFromString(msg_bytes)
        records.append(MessageToDict(msg, preserving_proto_field_name=True))

    return records


"""
─── LogBatch 格式解析 ───────────────────────────────────────────────────────

LogBatch 是旧版 AnyBatcher 使用的格式。整个文件就是一个 LogBatch protobuf 消息。

proto 定义（Source/common/santa.proto）:
  message LogBatch {
    repeated google.protobuf.Any records = 1;
  }

google.protobuf.Any 是 protobuf 的标准"类型擦除"包装:
  message Any {
    string type_url = 1;  // 类型标识，如 "type.googleapis.com/santa.pb.v1.SantaMessage"
    bytes value = 2;      // 内部消息的序列化字节
  }

所以解析流程: 反序列化 LogBatch → 遍历 records 数组 → 从每个 Any.value 解析 SantaMessage

C++ 读取代码: SNTCommandPrintLog.mm - ReadFromBatcher()
"""
def parse_logbatch_records(data: bytes) -> list[dict]:
    """解析 LogBatch 格式数据。整个 data 是一个 LogBatch protobuf。"""
    batch = santa_pb2.LogBatch()
    batch.ParseFromString(data)

    records = []
    for any_record in batch.records:
        # any_record.value 就是 SantaMessage 的 protobuf 序列化字节
        msg = santa_pb2.SantaMessage()
        msg.ParseFromString(any_record.value)
        records.append(MessageToDict(msg, preserving_proto_field_name=True))
    return records


"""
─── 格式检测 ────────────────────────────────────────────────────────────────

通过读取文件头的前几个字节，判断文件属于哪种格式。

关于 0x0A 的判断原理：
  LogBatch 的 proto 定义为 message LogBatch { repeated google.protobuf.Any records = 1; }
  records 字段编号=1, wire_type=2(length-delimited)
  protobuf 编码: tag = (field_number << 3) | wire_type = (1 << 3) | 2 = 0x0A
  所以 LogBatch 文件的第一个字节一定是 0x0A
"""
def detect_format(data: bytes) -> str:
    """根据文件头 magic number 判断格式类型:
    stream / zstd / gzip / logbatch / empty / unknown
    """
    if len(data) == 0:
        return "empty"

    # '<' = 小端序(Little-Endian), 'I' = 无符号32位整数(unsigned int)
    # 把文件头前 4 个字节当作一个 uint32 读出来
    magic = struct.unpack_from('<I', data, 0)[0]

    if magic == STREAM_BATCHER_MAGIC:
        return "stream"
    if magic == ZSTD_MAGIC:
        return "zstd"
    # gzip 只看低 16 位（只有 2 字节有效）
    if (magic & 0xFFFF) == GZIP_MAGIC:
        return "gzip"
    # protobuf tag 特征 → LogBatch
    if (data[0] & 0xFF) == 0x0A:
        return "logbatch"
    return "unknown"


"""
─── 解析入口 ────────────────────────────────────────────────────────────
思路: 先检测格式 → 压缩的先解压 → 解压后递归（解压出来可能是 stream 或 logbatch）
"""
def _parse_data(data: bytes) -> list[dict]:
    """检测数据格式并解析。压缩数据会先解压再递归调用自身。"""
    fmt = detect_format(data)
    if fmt == "stream":
        # Stream 格式: 逐条读取 magic+hash+length+protobuf
        return parse_stream_records(data)
    elif fmt == "logbatch":
        # LogBatch 格式: 整个文件是一个 protobuf
        return parse_logbatch_records(data)
    elif fmt == "gzip":
        # 先解压 gzip，解压后的内容仍是 stream 或 logbatch，递归处理
        return _parse_data(decompress_gzip(data))
    elif fmt == "zstd":
        # 先解压 zstd，同上
        return _parse_data(decompress_zstd(data))
    elif fmt == "empty":
        return []
    else:
        raise ValueError(f"Unsupported file format (first bytes: {data[:4].hex()})")


def parse_spool_file(file_path: str | Path) -> list[dict]:
    """读取一个 spool 文件，解析出所有 SantaMessage，返回 dict 列表。"""
    return _parse_data(Path(file_path).read_bytes())


def load_all_spool_messages(spool_dir: str) -> list[dict]:
    """遍历 spool 目录下所有文件，逐个解析并汇总全部 SantaMessage。"""
    all_messages = []
    # rglob('*') 递归遍历所有文件和子目录
    for file_path in sorted(Path(spool_dir).rglob('*')):
        if not file_path.is_file():
            continue
        try:
            messages = parse_spool_file(file_path)
            all_messages.extend(messages)
            print(f"  {file_path}: {len(messages)} messages")
        except Exception as e:
            print(f"  {file_path}: ERROR - {e}")
    return all_messages
