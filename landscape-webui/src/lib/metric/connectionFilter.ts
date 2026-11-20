import type { GetConnectHistoryParams } from "@landscape-router/types/api/schemas";

const emptyFilter = {
  src_ip: null,
  dst_ip: null,
  port_start: null,
  port_end: null,
  l3_proto: null,
  l4_proto: null,
  flow_id: null,
  gress: null,
  ifindex: null,
};

type ConnectionFilter = {
  [K in keyof typeof emptyFilter]: NonNullable<
    GetConnectHistoryParams[K]
  > | null;
};

export function createConnectionFilter(): ConnectionFilter {
  return { ...emptyFilter };
}
