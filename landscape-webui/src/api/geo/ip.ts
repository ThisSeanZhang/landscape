import {
  getGeoIps,
  getGeoIpRule,
  addGeoIp,
  addManyGeoIps,
  delGeoIp,
  getGeoIpCache,
  refreshGeoIpCache,
  searchGeoIpCache,
  getGeoIpCacheDetail,
  updateGeoIpByUpload as _updateGeoIpByUpload,
} from "@landscape-router/types/api/geo-ips/geo-ips";
import type {
  GeoFileCacheKey,
  QueryGeoKey,
  GeoIpConfig,
  GeoIpSourceConfig,
} from "@landscape-router/types/api/schemas";

export async function get_geo_ip_configs(
  name?: string,
): Promise<GeoIpSourceConfig[]> {
  return getGeoIps({ name });
}

export async function get_geo_ip_config(
  id: string,
): Promise<GeoIpSourceConfig> {
  return getGeoIpRule(id);
}

export async function push_geo_ip_config(
  config: GeoIpSourceConfig,
): Promise<void> {
  await addGeoIp(config);
}

export async function push_many_geo_ip_rule(
  rules: GeoIpSourceConfig[],
): Promise<void> {
  await addManyGeoIps(rules);
}

export async function delete_geo_ip_config(id: string): Promise<void> {
  await delGeoIp(id);
}

export async function get_geo_cache_key(
  filter: QueryGeoKey,
): Promise<GeoFileCacheKey[]> {
  return getGeoIpCache();
}

export async function refresh_geo_cache_key(): Promise<void> {
  await refreshGeoIpCache();
}

export async function search_geo_ip_cache(
  query: QueryGeoKey,
): Promise<GeoFileCacheKey[]> {
  return searchGeoIpCache({
    name: query.name ?? undefined,
    key: query.key ?? undefined,
  });
}

export async function get_geo_ip_cache_detail(
  key: GeoFileCacheKey,
): Promise<GeoIpConfig> {
  return getGeoIpCacheDetail(key);
}

export async function update_geo_ip_by_upload(
  name: string,
  form_data: FormData,
): Promise<void> {
  const file = form_data.get("file") as Blob;
  await _updateGeoIpByUpload(name, { file });
}
