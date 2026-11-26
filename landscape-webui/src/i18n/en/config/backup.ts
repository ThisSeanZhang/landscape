export default {
  backup_title: "Backup & Export",
  backup_desc:
    "You can export all current router configurations (including DNS, firewall, network interfaces, etc.) as an init file for quick recovery or migration.",
  export_init: "Export all current configurations as Init file",
  console_download_failed: "Failed to download config",

  import_init_desc:
    "Upload an init file to validate its version first. When Upload only is disabled, the file is saved as landscape_init.toml for the next initialization.",
  select_init_file: "Select Init File",
  upload_only: "Upload only and validate",
  import_init: "Import Init File",
  import_file_required: "Please select an init file",
  import_validate_success:
    "Init file validated successfully, version: {version}",
  import_install_success:
    "Init file saved for the next initialization, version: {version}. Initialization lock has been handled.",
  import_install_warning:
    "Disabling upload only overwrites landscape_init.toml in the config directory and removes the initialization lock. The next restart will initialize from this init file.",
};
