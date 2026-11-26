import backup from "./backup";
import dns from "./dns";
import lanHostname from "./lan_hostname";
import metric from "./metric/index";
import password from "./password";
import selfMonitor from "./self_monitor";
import time from "./time";
import ui from "./ui";

export default {
  directory: "Config Directory",
  welcome: "Welcome, {username}",

  default_enabled: "Default (enabled)",
  default_disabled: "Default (disabled)",
  option_enabled: "Enabled",
  option_disabled: "Disabled",
  empty_uses_default: "Leave empty to use the default value. Applied on save.",

  save_ui: "Save Settings",
  load_failed: "Failed to load configuration",
  save_success: "Save successful",
  save_failed: "Save failed",
  conflict: "Configuration conflict, please refresh and try again",

  ...backup,
  ...dns,
  ...lanHostname,
  ...metric,
  ...password,
  ...selfMonitor,
  ...time,
  ...ui,
};
