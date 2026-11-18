import backup from "./backup";
import dns from "./dns";
import lanHostname from "./lan_hostname";
import metric from "./metric/index";
import password from "./password";
import selfMonitor from "./self_monitor";
import time from "./time";
import ui from "./ui";

export default {
  directory: "配置目录",
  welcome: "欢迎, {username}",

  default_enabled: "默认（启用）",
  default_disabled: "默认（禁用）",
  option_enabled: "启用",
  option_disabled: "禁用",
  empty_uses_default: "留空使用默认值，保存后立即生效。",

  save_ui: "保存设置",
  load_failed: "加载配置失败",
  save_success: "保存成功",
  save_failed: "保存失败",
  conflict: "配置冲突，请刷新后重试",

  ...backup,
  ...dns,
  ...lanHostname,
  ...metric,
  ...password,
  ...selfMonitor,
  ...time,
  ...ui,
};
