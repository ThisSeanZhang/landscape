import { expect, it, vi } from "vitest";
import {
  pushEnrolledDevice,
  updateEnrolledDevice,
} from "@landscape-router/types/api/enrolled-devices/enrolled-devices";
import {
  create_enrolled_device,
  update_enrolled_device,
} from "./enrolled_device";

vi.mock(
  "@landscape-router/types/api/enrolled-devices/enrolled-devices",
  () => ({
    pushEnrolledDevice: vi.fn(),
    updateEnrolledDevice: vi.fn(),
  }),
);

it("omits optional blanks on create and update while retaining meaningful empty and zero values", async () => {
  const form = {
    mac: "02:00:00:00:00:01",
    name: "router",
    tag: [],
    hostname: " router ",
    ipv4: " ",
    dhcp_custom_options: [],
    dhcp_filter_options: [0],
    update_at: 0,
  };
  await create_enrolled_device(form);
  await update_enrolled_device("device-id", form);
  const expected = {
    mac: form.mac,
    name: "router",
    tag: [],
    hostname: "router",
    dhcp_filter_options: [0],
    update_at: 0,
  };
  for (const body of [
    vi.mocked(pushEnrolledDevice).mock.calls[0][0],
    vi.mocked(updateEnrolledDevice).mock.calls[0][1],
  ]) {
    expect(JSON.parse(JSON.stringify(body))).toEqual(expected);
  }
  expect(form.hostname).toBe(" router ");
});
