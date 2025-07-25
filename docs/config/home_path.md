# 配置存放目录文件介绍
当你使用命令 `landscape-webserver --help` 时可以看到有个 `-c, --config-dir <CONFIG_DIR>` 配置.

这个就是指定运行时项目的持久化配置存储路径位置. 检查目录你会看到如下内容:
```shell
root@router# tree 
.
├── cert.pem # 生成的自签名 证书
├── key.pem # 生成的自签名 证书
├── geo_tmp # geo 文件缓存路径
│   ├── ip 
│   └── site
├── landscape_api_token # api jwt token, 每次重启刷新
├── landscape_db.sqlite # sqlite 数据库文件位置
├── landscape_init.lock # lock 文件, 如果重新刷新配置
├── landscape_init.toml # 初始化配置文件 ( 仅读取一次 ) 介绍见 [配置文件介绍]
├── landscape.toml # 配置 日志 / 登录 用户 / 监听端口 等配置 介绍见 [配置文件介绍]
└── unix_link # 与 docker 容器通信的 sock 文件 忽略即可
    └── register.sock
```

