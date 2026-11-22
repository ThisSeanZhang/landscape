import * as ip from "./ip";
import * as site from "./site";

export const geoDatabases = {
  site: {
    lookupParam: "domain",
    listSources: site.get_geo_site_configs,
    search: site.search_geo_site_cache,
    lookup: site.lookup_geo_site_domain,
    detail: site.get_geo_site_cache_detail,
    refresh: site.refresh_geo_cache_key,
  },
  ip: {
    lookupParam: "ip",
    listSources: ip.get_geo_ip_configs,
    search: ip.search_geo_ip_cache,
    lookup: ip.lookup_geo_ip_address,
    detail: ip.get_geo_ip_cache_detail,
    refresh: ip.refresh_geo_cache_key,
  },
} as const;

export type GeoKind = keyof typeof geoDatabases;
