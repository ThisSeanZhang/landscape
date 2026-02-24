import type { LoginInfo } from "landscape-types/api/schemas";
import { loginHandler } from "landscape-types/api/auth/auth";

export async function do_login(login: LoginInfo) {
  return loginHandler(login);
}
