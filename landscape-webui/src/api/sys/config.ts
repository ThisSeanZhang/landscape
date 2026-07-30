import type {
  GetDnsConfigResponse,
  GetDnsConfigResponse as GetDnsConfigFastResponse,
  GetGatewayConfigResponse,
  GetLanHostnameConfigResponse,
  GetMetricConfigResponse,
  LandscapeGatewayConfig,
  LandscapeLanHostnameConfig,
  GetUIConfigResponse,
  LandscapeDnsConfig,
  LandscapeMetricConfig,
  LandscapeUIConfig,
  UpdateGatewayConfigRequest,
  UpdateLanHostnameConfigRequest,
  UpdateMetricConfigRequest,
  UpdateUIConfigRequest,
} from "@landscape-router/types/api/schemas";
import {
  exportInitConfig,
  importInitConfig,
  getUiConfigFast,
  getUiConfig,
  updateUiConfig,
  getMetricConfigFast,
  getMetricConfig,
  updateMetricConfig,
  getDnsConfigFast,
  getDnsConfig,
  updateDnsConfig,
  getLanHostnameConfigFast,
  getLanHostnameConfig,
  updateLanHostnameConfig,
  getGatewayConfigFast,
  getGatewayConfig,
  updateGatewayConfig,
} from "@landscape-router/types/api/system-config/system-config";
import i18n from "@/i18n";

/** Local type -- backend accepts serde_json::Value, so no ORVAL-generated request type exists. */
interface UpdateDnsConfigRequest {
  new_dns: LandscapeDnsConfig;
  expected_hash: string;
}

export async function get_init_config(): Promise<void> {
  try {
    const init_config = await exportInitConfig();
    const blob = new Blob([init_config.content], {
      type: "text/plain;charset=utf-8",
    });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = init_config.filename;
    document.body.appendChild(a);
    a.click();
    a.remove();

    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error(i18n.global.t("config.console_download_failed"), error);
  }
}

export async function import_init_config(file: File, upload_only: boolean) {
  return await importInitConfig({ file }, { upload_only });
}

export async function get_ui_config(): Promise<LandscapeUIConfig> {
  return await getUiConfigFast();
}

export async function get_ui_config_edit(): Promise<GetUIConfigResponse> {
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

export async function get_metric_config_edit(): Promise<GetMetricConfigResponse> {
  return await getMetricConfig();
}

export async function update_metric_config(
  payload: UpdateMetricConfigRequest,
): Promise<void> {
  await updateMetricConfig(payload);
}

export async function get_dns_config(): Promise<GetDnsConfigFastResponse> {
  return await getDnsConfigFast();
}

export async function get_dns_config_edit(): Promise<GetDnsConfigResponse> {
  return await getDnsConfig();
}

export async function update_dns_config(
  payload: UpdateDnsConfigRequest,
): Promise<void> {
  await updateDnsConfig(payload);
}

export async function get_lan_hostname_config(): Promise<LandscapeLanHostnameConfig> {
  return await getLanHostnameConfigFast();
}

export async function get_lan_hostname_config_edit(): Promise<GetLanHostnameConfigResponse> {
  return await getLanHostnameConfig();
}

export async function update_lan_hostname_config(
  payload: UpdateLanHostnameConfigRequest,
): Promise<void> {
  await updateLanHostnameConfig(payload);
}

export async function get_gateway_config(): Promise<LandscapeGatewayConfig> {
  return await getGatewayConfigFast();
}

export async function get_gateway_config_edit(): Promise<GetGatewayConfigResponse> {
  return await getGatewayConfig();
}

export async function update_gateway_config(
  payload: UpdateGatewayConfigRequest,
): Promise<void> {
  await updateGatewayConfig(payload);
}
