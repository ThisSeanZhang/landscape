import {
  listCerts,
  getCert,
  createCert,
  deleteCert,
  issueCert,
  revokeCert,
  renewCert,
} from "@landscape-router/types/api/certificates/certificates";
import type { CertConfig } from "@landscape-router/types/api/schemas";

export async function get_certs(): Promise<CertConfig[]> {
  return listCerts();
}

export async function get_cert(id: string): Promise<CertConfig> {
  return getCert(id);
}

export async function push_cert(config: CertConfig): Promise<CertConfig> {
  return createCert(config);
}

export async function delete_cert(id: string): Promise<void> {
  await deleteCert(id);
}

export async function issue_cert(id: string): Promise<CertConfig> {
  return issueCert(id);
}

export async function revoke_cert(id: string): Promise<CertConfig> {
  return revokeCert(id);
}

export async function renew_cert(id: string): Promise<CertConfig> {
  return renewCert(id);
}
