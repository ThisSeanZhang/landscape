export default {
  title: "Device Management",
  edit_title: "Edit Device Binding",
  add_title: "Add Device Binding",

  name: "Display Name",
  name_placeholder: "e.g. My phone",
  name_required: "Please enter a display name",

  mac: "MAC Address",
  mac_placeholder: "00:11:22:33:44:55",
  mac_required: "MAC address is required",
  mac_invalid: "Please enter a valid MAC address (XX:XX:XX:XX:XX:XX)",

  iface: "Network",
  iface_placeholder: "Select interface (optional)",
  iface_none: "No restriction (global)",

  fake_name: "Privacy Name",
  fake_name_placeholder: "Optional: display name in privacy mode",

  ipv4: "IPv4 Binding",
  ipv4_placeholder: "Optional: 192.168.x.x",
  ipv4_invalid: "Please enter a valid IP address",
  ipv4_out_of_range: "IP is outside DHCP range of interface {iface}",

  ipv6: "IPv6 Binding",
  ipv6_placeholder: "Optional: IPv6 address",

  tag: "Tag",
  remark: "Remark",
  remark_placeholder: "More details about this device...",

  save_success: "Saved successfully",
  cancel: "Cancel",
  save: "Save",

  empty_desc: "No device bindings yet",
  add_now: "Add now",
  add_btn: "Add Device",
  delete_confirm: "Are you sure you want to delete this device binding?",
  delete_title: "Confirm Deletion",

  invalid_status: "Invalid Configuration",
  invalid_bindings_title: "Detected invalid IP-MAC bindings",
  invalid_bindings_warning:
    "After DHCP changes on interface {iface}, {count} IP-MAC bindings are out of current subnet. Please update them.",
  go_to_manage: "Go to manage",
};
