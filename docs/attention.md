
# 注意事项

## 内核版本
需要使用内核版本在 6.9.x 以上的版本进行部署。

## 需要检查的内核配置
检查一编译配置文件是否如下进行配置
```text
CONFIG_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y
# BPF subsystem
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
# CONFIG_BPF_JIT_ALWAYS_ON is not set
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
# CONFIG_BPF_PRELOAD is not set
CONFIG_BPF_LSM=y
# end of BPF subsystem
CONFIG_CGROUP_BPF=y
CONFIG_IPV6_SEG6_BPF=y
CONFIG_NETFILTER_BPF_LINK=y
CONFIG_NETFILTER_XT_MATCH_BPF=m
CONFIG_NET_CLS_BPF=m
CONFIG_NET_ACT_BPF=m
CONFIG_BPF_STREAM_PARSER=y
CONFIG_LWTUNNEL_BPF=y
# HID-BPF support
# CONFIG_HID_BPF is not set
# end of HID-BPF support
CONFIG_BPF_EVENTS=y
CONFIG_TEST_BPF=m
```


## 内核 BTF 生成需要开启
选择
**Kernel hacking**   
  -> **Compile-time checks and compiler options**   
    -> **Debug information (Generate DWARF Version 5 debuginfo)**  
即可在 
**Kernel hacking**   
  -> **Compile-time checks and compiler options**  
看到 **Generate BTF type information**
选中安装即可


