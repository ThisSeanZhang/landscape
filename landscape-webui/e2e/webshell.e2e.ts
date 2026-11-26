import type { Locator, Page } from "@playwright/test";
import { expect, test } from "./fixtures";

async function drag(page: Page, handle: Locator, dx: number, dy: number) {
  await expect(handle).toBeInViewport();
  const rect = (await handle.boundingBox())!;
  const x = rect.x + rect.width / 2;
  const y = rect.y + rect.height / 2;
  await page.mouse.move(x, y);
  await page.mouse.down();
  await page.mouse.move(x + dx, y + dy, { steps: 8 });
  await page.mouse.up();
}

test("resized docks and floating drawers keep their own dimensions across mode switches", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 650 });
  let connections = 0;
  const input: string[] = [];
  await page.routeWebSocket("**/api/ws/pty/**", (socket) => {
    connections++;
    socket.onMessage((message) => {
      const frame = JSON.parse(message.toString());
      if (frame.t === "data") input.push(String.fromCharCode(...frame.data));
    });
  });
  await page.goto("/");
  await page.getByTitle("WebShell").click();
  const dock = page.locator(".terminal-dock");
  const drawer = page.locator(".terminal-drawer");
  const handle = dock.locator(".resize-handle");
  await drag(page, handle, -520, 0);
  const rightWidth = (await dock.boundingBox())!.width;
  expect(rightWidth).toBeGreaterThan(850);
  await dock.getByRole("button", { name: "Switch to bottom" }).click();
  await expect(dock).toHaveCSS("height", "400px");
  await expect(dock.getByRole("button", { name: "Close" })).toBeInViewport({
    ratio: 1,
  });
  await drag(page, handle, 0, 100);
  const bottomHeight = (await dock.boundingBox())!.height;

  await dock.getByRole("button", { name: "Float Mode" }).click();
  await expect(drawer).toHaveCSS("height", "400px");
  await drag(page, drawer.locator(".n-drawer__resize-trigger"), 0, 75);
  const floatHeight = (await drawer.boundingBox())!.height;
  expect(floatHeight).toBeLessThan(350);
  await drawer.getByRole("button", { name: "Switch to right" }).click();
  await expect(drawer).toHaveCSS("width", "500px");
  await drawer
    .getByRole("button", { name: "Full screen", exact: true })
    .click();
  await expect(drawer).toHaveCSS("width", "1440px");
  await drawer.getByRole("button", { name: "Dock Mode" }).click();
  await expect(dock).toHaveCSS("width", rightWidth + "px");
  await dock.getByRole("button", { name: "Float Mode" }).click();
  await expect(drawer).toHaveCSS("width", "500px");
  await drawer.getByRole("button", { name: "Switch to bottom" }).click();
  await expect(drawer).toHaveCSS("height", floatHeight + "px");
  await drawer.getByRole("button", { name: "Dock Mode" }).click();
  await expect(dock).toHaveCSS("height", bottomHeight + "px");
  await dock.locator("textarea").press("x");
  await expect.poll(() => input.join("")).toBe("x");
  expect(connections).toBe(1);
  await dock.getByRole("button", { name: "Close" }).click();
  await expect(dock).toHaveCount(0);
});

test("a legacy oversized dock keeps its title and controls inside a shrinking viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 580 });
  await page.addInitScript(() => {
    localStorage.setItem("landscape-pty-dock-position", "bottom");
    localStorage.setItem("landscape-pty-dock-size", "1100");
  });
  await page.goto("/");
  await page.getByTitle("WebShell").click();
  const dock = page.locator(".terminal-dock");
  const close = dock.getByRole("button", { name: "Close" });
  for (const viewport of [
    { width: 390, height: 580 },
    { width: 620, height: 320 },
  ]) {
    await page.setViewportSize(viewport);
    await expect(dock.getByText("Web Shell", { exact: true })).toBeInViewport({
      ratio: 1,
    });
    await expect(close).toBeInViewport({ ratio: 1 });
    await expect(dock.locator(".resize-handle")).toBeInViewport({ ratio: 1 });
    const header = (await page.locator(".app-header").boundingBox())!;
    expect((await dock.boundingBox())!.y).toBeGreaterThanOrEqual(
      header.y + header.height,
    );
  }
  await drag(page, dock.locator(".resize-handle"), 0, 45);
  await expect
    .poll(() => dock.evaluate((el) => el.clientHeight))
    .toBeLessThan(250);
  await dock.getByRole("button", { name: "Switch to right" }).click();
  await expect(dock).toHaveCSS("width", "400px");
  await page.setViewportSize({ width: 320, height: 560 });
  await expect(close).toBeInViewport({ ratio: 1 });
  await close.click();
  await expect(dock).toHaveCount(0);
});
