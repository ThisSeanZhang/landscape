import type {
  GetDnsConfig200Data,
  GetDnsConfigFast200Data,
  GetMetricConfig200Data,
  GetUiConfig200Data,
  LandscapeDnsConfig,
  LandscapeMetricConfig,
  LandscapeUIConfig,
  UpdateMetricConfigRequest,
  UpdateUIConfigRequest,
} from "landscape-types/api/schemas";
import {
  exportInitConfig,
  getUiConfigFast,
  getUiConfig,
  updateUiConfig,
  getMetricConfigFast,
  getMetricConfig,
  updateMetricConfig,
  getDnsConfigFast,
  getDnsConfig,
  updateDnsConfig,
} from "landscape-types/api/system-config/system-config";

/** Local type -- backend accepts serde_json::Value, so no ORVAL-generated request type exists. */
interface UpdateDnsConfigRequest {
  new_dns: LandscapeDnsConfig;
  expected_hash: string;
}

export async function get_init_config(): Promise<void> {
  try {
    const jsonStr = await exportInitConfig();

    const filename = "landscape_init.toml";

    const blob = new Blob([jsonStr], { type: "application/octet-stream" });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();

    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error("下载配置失败", error);
  }
}

export async function get_ui_config(): Promise<LandscapeUIConfig> {
  return await getUiConfigFast();
}

export async function get_ui_config_edit(): Promise<GetUiConfig200Data> {
  return await getUiConfig();
}

export async function update_ui_config(
  payload: UpdateUIConfigRequest,
): Promise<void> {
  await updateUiConfig(payload);
}

export async function get_metric_config(): Promise<LandscapeMetricConfig> {
  return await getMetricConfigFast();
}

export async function get_metric_config_edit(): Promise<GetMetricConfig200Data> {
  return await getMetricConfig();
}

export async function update_metric_config(
  payload: UpdateMetricConfigRequest,
): Promise<void> {
  await updateMetricConfig(payload);
}

export async function get_dns_config(): Promise<GetDnsConfigFast200Data> {
  return await getDnsConfigFast();
}

export async function get_dns_config_edit(): Promise<GetDnsConfig200Data> {
  return await getDnsConfig();
}

export async function update_dns_config(
  payload: UpdateDnsConfigRequest,
): Promise<void> {
  await updateDnsConfig(payload);
}
