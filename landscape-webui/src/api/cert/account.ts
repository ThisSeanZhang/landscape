import {
  listCertAccounts,
  getCertAccount,
  createCertAccount,
  deleteCertAccount,
} from "@landscape-router/types/api/certificate-accounts/certificate-accounts";
import type { CertAccountConfig } from "@landscape-router/types/api/schemas";

export async function get_cert_accounts(): Promise<CertAccountConfig[]> {
  return listCertAccounts();
}

export async function get_cert_account(id: string): Promise<CertAccountConfig> {
  return getCertAccount(id);
}

export async function push_cert_account(
  config: CertAccountConfig,
): Promise<CertAccountConfig> {
  return createCertAccount(config);
}

export async function delete_cert_account(id: string): Promise<void> {
  await deleteCertAccount(id);
}
