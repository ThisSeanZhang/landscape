### 如果需要在 x86 下进行交叉编译
> 目前的步骤仅在 Debian 下进行验证

## ARMv7
#### 确保 Rust 工具链支持交叉编译
使用 `rustup` 安装 Rust 工具链并添加 `aarch64` 目标：
```bash
rustup target add armv7-unknown-linux-gnueabihf
```
#### 安装交叉编译依赖
在进行交叉编译时，Rust 会调用目标架构的链接器，因此需要安装对应的工具链。

```bash
# 启用 ARM64 架构支持
sudo dpkg --add-architecture armhf
sudo apt update

sudo apt install gcc-arm-linux-gnueabihf libelf-dev:armhf zlib1g-dev:armhf
```

**检查安装是否成功**：
```bash
arm-linux-gnueabihf-gcc --version
```

#### 进行交叉编译
完成依赖安装后，可以运行以下命令进行交叉编译：

```bash
cargo build --release --target armv7-unknown-linux-gnueabihf
```

## ARM64
#### 确保 Rust 工具链支持交叉编译
使用 `rustup` 安装 Rust 工具链并添加 `aarch64` 目标：
```bash
rustup target add aarch64-unknown-linux-gnu
```

#### 安装交叉编译依赖
在进行交叉编译时，Rust 会调用目标架构的链接器，因此需要安装对应的工具链。

```bash
# 启用 ARM64 架构支持
sudo dpkg --add-architecture arm64
sudo apt update

sudo apt install gcc-aarch64-linux-gnu libelf-dev:arm64 zlib1g-dev:arm64
```

**检查安装是否成功**：
```bash
aarch64-linux-gnu-gcc --version
```

#### 进行交叉编译
完成依赖安装后，可以运行以下命令进行交叉编译：

```bash
cargo build --release --target aarch64-unknown-linux-gnu
```

