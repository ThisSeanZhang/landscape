export default {
  backup_title: "备份与导出",
  backup_desc:
    "你可以将当前路由器的所有配置（除 Docker 相关）导出为一个初始化文件，用于快速恢复或迁移。",
  export_init: "导出当前所有配置为 Init 文件",
  console_download_failed: "下载配置失败",

  import_init_desc:
    "上传 Init 文件会先校验版本。关闭“仅上传”后，会把该文件保存为下一次初始化使用的 landscape_init.toml。",
  select_init_file: "选择 Init 文件",
  upload_only: "仅上传并校验",
  import_init: "导入 Init 文件",
  import_file_required: "请选择一个 Init 文件",
  import_validate_success: "Init 文件校验成功，版本: {version}",
  import_install_success:
    "Init 文件已保存为下一次初始化文件，版本: {version}，初始化 lock 已处理",
  import_install_warning:
    "关闭仅上传会覆盖配置目录中的 landscape_init.toml，并删除初始化 lock。下次重启将按该 Init 文件重新初始化。",
};
