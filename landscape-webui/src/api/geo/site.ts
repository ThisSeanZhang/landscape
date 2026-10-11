import {
  getGeoSites,
  getGeoRule,
  addGeoSite,
  addManyGeoSites,
  delGeoSite,
  getGeoSiteCache,
  refreshGeoSiteCache,
  refreshGeoSiteConfigByName,
  searchGeoSiteCache,
  lookupGeoSiteDomain,
  getGeoSiteCacheDetail,
  updateGeoSiteByUpload as _updateGeoSiteByUpload,
  getGeoSiteTasks,
  cancelGeoSiteTask,
} from "@landscape-router/types/api/geo-sites/geo-sites";
import type {
  GeoFileCacheKey,
  QueryGeoKey,
  GeoDomainConfig,
  GeoSiteSourceConfig,
  GeoSiteLookupResult,
  GeoTaskProgress,
} from "@landscape-router/types/api/schemas";

export type { GeoSiteLookupResult, GeoTaskProgress };

export async function lookup_geo_site_domain(
  domain: string,
): Promise<GeoSiteLookupResult[]> {
  return lookupGeoSiteDomain({ domain });
}

export async function get_geo_site_configs(
  name?: string,
): Promise<GeoSiteSourceConfig[]> {
  return getGeoSites({ name });
}

export async function get_geo_site_config(
  id: string,
): Promise<GeoSiteSourceConfig> {
  return getGeoRule(id);
}

export async function push_geo_site_config(
  config: GeoSiteSourceConfig,
): Promise<void> {
  await addGeoSite(config);
}

export async function push_many_geo_site_rule(
  rules: GeoSiteSourceConfig[],
): Promise<void> {
  await addManyGeoSites(rules);
}

export async function delete_geo_site_config(id: string): Promise<void> {
  await delGeoSite(id);
}

export async function get_geo_cache_key(
  filter: QueryGeoKey,
): Promise<GeoFileCacheKey[]> {
  return getGeoSiteCache();
}

export async function refresh_geo_cache_key(): Promise<void> {
  await refreshGeoSiteCache();
}

export async function search_geo_site_cache(
  query: QueryGeoKey,
): Promise<GeoFileCacheKey[]> {
  return searchGeoSiteCache({
    name: query.name ?? undefined,
    key: query.key ?? undefined,
  });
}

export async function get_geo_site_cache_detail(
  key: GeoFileCacheKey,
): Promise<GeoDomainConfig> {
  return getGeoSiteCacheDetail(key);
}

export async function update_geo_site_by_upload(
  name: string,
  form_data: FormData,
): Promise<void> {
  const file = form_data.get("file") as Blob;
  await _updateGeoSiteByUpload(name, { file });
}

export async function refresh_geo_site_by_name(name: string): Promise<void> {
  await refreshGeoSiteConfigByName(name);
}

export async function get_geo_site_tasks(): Promise<GeoTaskProgress[]> {
  return getGeoSiteTasks();
}

export async function cancel_geo_site_task(id: string): Promise<boolean> {
  return cancelGeoSiteTask(id);
}
