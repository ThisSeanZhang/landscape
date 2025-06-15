import axiosService from "@/api";
import { GeoConfigKey, QueryGeoKey } from "@/rust_bindings/common/geo";
import {
  GeoDomainConfig,
  GeoSiteSourceConfig,
} from "@/rust_bindings/common/geo_site";

export async function get_geo_site_configs(
  name?: string
): Promise<GeoSiteSourceConfig[]> {
  let data = await axiosService.get(`config/geo_sites`, {
    params: {
      name,
    },
  });
  return data.data;
}

export async function get_geo_site_config(
  id: string
): Promise<GeoSiteSourceConfig> {
  let data = await axiosService.get(`config/geo_sites/${id}`);
  return data.data;
}

export async function push_geo_site_config(
  config: GeoSiteSourceConfig
): Promise<void> {
  let data = await axiosService.post(`config/geo_sites`, config);
}

export async function push_many_geo_site_rule(
  rules: GeoSiteSourceConfig[]
): Promise<void> {
  let data = await axiosService.post(`config/geo_sites/set_many`, rules);
}

export async function delete_geo_site_config(id: string): Promise<void> {
  let data = await axiosService.delete(`config/geo_sites/${id}`);
}

export async function get_geo_cache_key(
  filter: QueryGeoKey
): Promise<GeoConfigKey[]> {
  let data = await axiosService.get(`config/geo_sites/cache`, {
    params: { ...filter },
  });
  return data.data;
}

export async function refresh_geo_cache_key(): Promise<void> {
  let data = await axiosService.post(`config/geo_sites/cache`);
}

export async function search_geo_site_cache(
  query: QueryGeoKey
): Promise<GeoConfigKey[]> {
  let data = await axiosService.get(`config/geo_sites/cache/search`, {
    params: {
      ...query,
    },
  });
  return data.data;
}

export async function get_geo_site_cache_detail(
  key: GeoConfigKey
): Promise<GeoDomainConfig> {
  let data = await axiosService.get(`config/geo_sites/cache/detail`, {
    params: {
      ...key,
    },
  });
  return data.data;
}
