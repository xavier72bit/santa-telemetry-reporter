#!/usr/bin/env python3
import json
import sys
import os
import shutil
import subprocess


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# 版本 -> proto 文件列表的映射
with open(os.path.join(BASE_DIR, "version_protofiles.json")) as f:
    PROTO_MAPPING = json.load(f)


def print_version_info():
    if not PROTO_MAPPING:
        print("可用版本: (空)")
    else:
        available = ", ".join(sorted(PROTO_MAPPING.keys()))
        print(f"可用版本: {available}")


def main():
    if len(sys.argv) < 3 or not sys.argv[1].strip() or not sys.argv[2].strip():
        print(f"参数: <SANTA_SRC_DIR> <SANTA_VERSION>")
        sys.exit(1)

    santa_src_dir = os.path.abspath(sys.argv[1])
    santa_version = sys.argv[2].strip()

    # ---------------------------------------------------------------------
    # 前置检查
    # ---------------------------------------------------------------------

    if not os.path.isdir(santa_src_dir):
        print(f"错误: 找不到 Santa 源码目录: {santa_src_dir}")
        sys.exit(1)

    # 检查版本是否存在
    if santa_version not in PROTO_MAPPING:
        print(f"错误: 版本 '{santa_version}' 不在映射中")
        print_version_info()
        sys.exit(1)

    proto_files = PROTO_MAPPING[santa_version]
    if not proto_files:
        print(f"错误: 版本 '{santa_version}' 的 proto 文件列表为空，编译终止。")
        sys.exit(1)

    # ---------------------------------------------------------------------
    # 同步 proto 文件到目标目录
    # ---------------------------------------------------------------------
    full_target_paths = []

    for rel_path in proto_files:
        src_file = os.path.join(santa_src_dir, rel_path)
        dest_file = os.path.join(BASE_DIR, rel_path)

        if not os.path.isfile(src_file):
            print(f"警告: 源码中未找到文件: {rel_path} ，跳过。")
            continue

        dest_dir = os.path.dirname(dest_file)
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(src_file, dest_file)
        print(f"  已同步: {rel_path}")

        full_target_paths.append(dest_file)

    if not full_target_paths:
        print("错误: 未拷贝任何文件，编译终止。")
        sys.exit(1)

    # ---------------------------------------------------------------------
    # 调用 protoc 编译
    # ---------------------------------------------------------------------
    print("正在调用 protoc 进行编译...")

    # 执行命令并对接标准输出/错误
    result = subprocess.run(
        [
            "protoc",
            "-I", BASE_DIR,
            "--python_out", BASE_DIR
        ] + full_target_paths
    )

    if result.returncode == 0:
        print(f"编译完成")
    else:
        print("编译失败，请检查上面的 protoc 报错信息。")
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()
