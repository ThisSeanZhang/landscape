import { MessageApi } from "naive-ui";

export class Range {
  start: number;
  end: number;

  constructor(start: number, end: number) {
    this.start = start;
    this.end = end;
  }
}

export type KeyValuePair = { key: string; value: string };

export class SimpleResult {
  success: boolean;

  constructor(obj?: { success?: boolean }) {
    this.success = obj?.success ?? false;
  }
}

export const LANDSCAPE_TOKEN_KEY = "LANDSCAPE_TOKEN";

export async function copy_context_to_clipboard(
  message: MessageApi,
  content: string,
) {
  try {
    await navigator.clipboard.writeText(content);
    message.success("copy success");
  } catch (e) {
    message.error("copy fail");
  }
}

export async function read_context_from_clipboard(): Promise<string> {
  return await navigator.clipboard.readText();
}

/**
 * 检测是否为 IPv4 地址
 */
export function is_ipv4(value: string): boolean {
  return /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/.test(
    value,
  );
}

/**
 * 检测是否为 IPv6 地址
 */
export function is_ipv6(value: string): boolean {
  return /^(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}$|::/.test(value);
}

/**
 * 检测是否为 MAC 地址
 */
export function is_mac(value: string): boolean {
  return /^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$/.test(value);
}

/**
 * IPv4 专门打码：遮蔽头尾，展示中间
 * 192.168.1.123 -> ***.168.1.***
 */
export function mask_ipv4(value: string): string {
  const parts = value.split(".");
  if (parts.length !== 4) return value;
  return `***.${parts[1]}.${parts[2]}.***`;
}

/**
 * IPv6 专门打码：遮蔽头尾，展示中间
 */
export function mask_ipv6(value: string): string {
  const parts = value.split(":");
  if (parts.length < 3) return value;
  // 遮蔽前两个和后两个（如果足够长）
  const maskCount = parts.length > 4 ? 2 : 1;
  return parts
    .map((p, i) => {
      if (i < maskCount || i >= parts.length - maskCount) return "****";
      return p;
    })
    .join(":");
}

/**
 * MAC 专门打码：遮蔽头尾，展示中间
 * AA:BB:CC:DD:EE:FF -> **:BB:CC:DD:EE:**
 */
export function mask_mac(value: string): string {
  const separator = value.includes(":") ? ":" : "-";
  const parts = value.split(separator);
  if (parts.length !== 6) return value;
  return `**${separator}${parts[1]}${separator}${parts[2]}${separator}${parts[3]}${separator}${parts[4]}${separator}**`;
}

export function mask_string(value: string | undefined | null): string {
  if (!value) return "***";

  if (is_mac(value)) return mask_mac(value);
  if (is_ipv4(value)) return mask_ipv4(value);
  if (is_ipv6(value)) return mask_ipv6(value);

  const length = value.length;

  if (length <= 4) {
    return value.substring(0, 1) + "*****";
  } else if (length <= 10) {
    return value.substring(0, 3) + "*****";
  } else {
    const start = Math.floor((length - 5) / 2);
    return "*****" + value.substring(start, start + 5) + "*****";
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
