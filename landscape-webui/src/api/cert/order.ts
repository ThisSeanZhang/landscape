import {
  listCertOrders,
  getCertOrder,
  createCertOrder,
  deleteCertOrder,
} from "@landscape-router/types/api/certificate-orders/certificate-orders";
import type { CertOrderConfig } from "@landscape-router/types/api/schemas";

export async function get_cert_orders(): Promise<CertOrderConfig[]> {
  return listCertOrders();
}

export async function get_cert_order(id: string): Promise<CertOrderConfig> {
  return getCertOrder(id);
}

export async function push_cert_order(
  config: CertOrderConfig,
): Promise<CertOrderConfig> {
  return createCertOrder(config);
}

export async function delete_cert_order(id: string): Promise<void> {
  await deleteCertOrder(id);
}
