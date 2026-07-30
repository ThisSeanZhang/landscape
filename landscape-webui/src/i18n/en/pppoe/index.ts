export default {
  editor: {
    title: "Edit PPPD Service",
    default_route: "Set as Default Route",
    ppp_iface_name: "PPP Interface Name",
    iface_required: "Interface name is required",
    iface_invalid_format:
      "PPPoE interface names may only use letters, digits, '-' and '_', must be 15 characters or fewer, and cannot have leading or trailing whitespace",
    iface_same_as_attach:
      "PPPoE interface name cannot be the same as the attached interface",
    iface_conflict_existing:
      "PPPoE interface name cannot conflict with an existing interface",
    username: "Username",
    password: "Password",
    ac_name:
      "Requested AC name (leave empty unless needed, otherwise dialing may fail)",
    ac_name_tip:
      "When set, connection is limited to servers with matching AC name",
    plugin: "PPPoE Plugin",
  },
  pppd_card: {
    interface_label: "Interface: {iface_name}",
    attach_interface: "Attached Interface",
  },
  pppd_drawer: {
    configure_pppd: "Configure {iface_name} PPPD Service",
    add_pppd: "Add PPPD Config",
  },
};
