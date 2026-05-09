export type {
  CustomDhcpOption,
  DhcpV4DnrOptionConfig,
  RelayAgentInfo,
} from "@landscape-router/types/api/schemas";

export const DHCP_OPTION_LABELS: Record<number, string> = {
  12: "Host Name (12)",
  15: "Domain Name (15)",
  28: "Broadcast Address (28)",
  43: "Vendor Extensions (43)",
  66: "TFTP Server Name (66)",
  67: "Bootfile Name (67)",
  82: "Relay Agent Information (82)",
  162: "Encrypted DNS Discovery (162)",
};

export const DHCP_FILTER_OPTIONS = [12, 15, 28, 43, 66, 67, 82, 162] as const;
