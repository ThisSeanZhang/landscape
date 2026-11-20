import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { usePolling } from "./usePolling";

const page = Object.assign(new EventTarget(), { hidden: false });

beforeEach(() => {
  page.hidden = false;
  vi.stubGlobal("document", page);
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it("waits for the slow round to finish before scheduling another", async () => {
  let finish!: () => void;
  const refresh = vi.fn().mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
  );
  const polling = usePolling(refresh);
  polling.start(vi.fn());
  await vi.advanceTimersByTimeAsync(9000);
  expect(refresh).toHaveBeenCalledTimes(1);
  finish();
  await vi.advanceTimersByTimeAsync(2999);
  expect(refresh).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(refresh).toHaveBeenCalledTimes(2);
  polling.stop();
});

it("resumes after remount, even if the previous session fails late", async () => {
  let fail!: (error: Error) => void;
  const refresh = vi.fn().mockImplementationOnce(
    () =>
      new Promise<void>((_, reject) => {
        fail = reject;
      }),
  );
  const polling = usePolling(refresh);
  polling.start(vi.fn());
  const oldSession = refresh.mock.calls[0][0];
  polling.stop();
  expect(oldSession()).toBe(false);
  page.hidden = true;
  polling.start(vi.fn());
  page.hidden = false;
  page.dispatchEvent(new Event("visibilitychange"));
  expect(refresh).toHaveBeenCalledTimes(1);
  fail(new Error("old session"));
  await vi.advanceTimersByTimeAsync(0);
  expect(refresh).toHaveBeenCalledTimes(2);
  expect(polling.enable_interval.value).toBe(true);
  page.hidden = true;
  page.dispatchEvent(new Event("visibilitychange"));
  await vi.advanceTimersByTimeAsync(6000);
  expect(refresh).toHaveBeenCalledTimes(2);
  page.hidden = false;
  page.dispatchEvent(new Event("visibilitychange"));
  expect(refresh).toHaveBeenCalledTimes(3);
  polling.stop();
  page.dispatchEvent(new Event("visibilitychange"));
  await vi.advanceTimersByTimeAsync(6000);
  expect(refresh).toHaveBeenCalledTimes(3);
});
