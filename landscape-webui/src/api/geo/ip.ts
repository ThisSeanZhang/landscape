import axiosService from "@/api";
import { GeoConfigKey, QueryGeoKey } from "@/rust_bindings/common/geo";
import { GeoIpConfig, GeoIpSourceConfig } from "@/rust_bindings/common/geo_ip";

export async function get_geo_ip_configs(
  name?: string
): Promise<GeoIpSourceConfig[]> {
  let data = await axiosService.get(`config/geo_ips`, {
    params: {
      name,
    },
  });
  return data.data;
}

export async function get_geo_ip_config(
  id: string
): Promise<GeoIpSourceConfig> {
  let data = await axiosService.get(`config/geo_ips/${id}`);
  return data.data;
}

export async function push_geo_ip_config(
  config: GeoIpSourceConfig
): Promise<void> {
  let data = await axiosService.post(`config/geo_ips`, config);
}

export async function push_many_geo_ip_rule(
  rules: GeoIpSourceConfig[]
): Promise<void> {
  let data = await axiosService.post(`config/geo_ips/set_many`, rules);
}

export async function delete_geo_ip_config(id: string): Promise<void> {
  let data = await axiosService.delete(`config/geo_ips/${id}`);
}

export async function get_geo_cache_key(
  filter: QueryGeoKey
): Promise<GeoConfigKey[]> {
  let data = await axiosService.get(`config/geo_ips/cache`, {
    params: { ...filter },
  });
  return data.data;
}

export async function refresh_geo_cache_key(): Promise<void> {
  let data = await axiosService.post(`config/geo_ips/cache`);
}

export async function search_geo_ip_cache(
  query: QueryGeoKey
): Promise<GeoConfigKey[]> {
  let data = await axiosService.get(`config/geo_ips/cache/search`, {
    params: {
      ...query,
    },
  });
  return data.data;
}

export async function get_geo_ip_cache_detail(
  key: GeoConfigKey
): Promise<GeoIpConfig> {
  let data = await axiosService.get(`config/geo_ips/cache/detail`, {
    params: {
      ...key,
    },
  });
  return data.data;
}
