import {
  getGeoSites,
  getGeoRule,
  addGeoSite,
  addManyGeoSites,
  delGeoSite,
  getGeoSiteCache,
  refreshGeoSiteCache,
  searchGeoSiteCache,
  getGeoSiteCacheDetail,
  updateGeoSiteByUpload as _updateGeoSiteByUpload,
} from "landscape-types/api/geo-sites/geo-sites";
import type {
  GeoFileCacheKey,
  QueryGeoKey,
  GeoDomainConfig,
  GeoSiteSourceConfig,
} from "landscape-types/api/schemas";

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
