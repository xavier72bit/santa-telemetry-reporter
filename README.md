# Santa Telemetry Reporter

[santa](https://github.com/northpolesec/santa) monitoring mode event analyzer and reporter.


# USAGE

1. 建议将spool文件拷贝到当前目录下再进行分析
```bash
rm -rf spool && sudo rsync -a /var/db/santa/spool/ ./spool/ && sudo chown -R $USER ./spool/
```

2. 生成proto文件
```bash
python proto/build_proto.py <SANTA_SRC_DIR> <SANTA_VERSION>
```

3. make install // TODO


# DEVELOPMENT

deserializer由Rust扩展实现，实践参考：https://github.com/xavier72bit/python-rust-demo
