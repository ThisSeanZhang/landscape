# 编译

## 依赖安装
请确保安装以下依赖：
```shell
sudo apt install build-essential clang libelf1 libelf-dev zlib1g-dev make pkg-config
```

## 编译步骤
确保系统已安装 `node`、`yarn` 和 `rust`，然后运行以下命令进行编译：
```shell
./build.sh
```

选择需要编译的架构

```text
No target specified.
Supported architectures:
1) aarch64
2) x86_64
3) Use default architecture (x86_64)
Please select a target architecture by entering the corresponding number [default = x86_64]: 
```

编译完成后，产物将存放在 `output` 文件夹中。

如果需要在 x86 主机上进行交叉编译，请参考 [交叉编译 aarch64](cross.md)
