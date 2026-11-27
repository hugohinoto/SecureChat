import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("device registration is automatic and chat UI has no manual sync or duplicate controls", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const settings = await readFile(new URL("../public/settings.html", import.meta.url), "utf8");
  const settingsJs = await readFile(new URL("../public/settings.js", import.meta.url), "utf8");

  assert.doesNotMatch(html, /端末管理|crypto-v2-device-list|device-manage-sidebar-button/);
  assert.match(settings, /id="settings-devices"/);
  assert.match(settings, /id="crypto-v2-device-list"/);
  assert.match(settingsJs, /\/api\/crypto\/devices/);
  assert.match(settingsJs, /\/revoke/);
  assert.doesNotMatch(html, /device-register-all-button|crypto-v2-devices-toggle|sidebar-device-status|登録済み\s*·\s*この端末|全チャットを今すぐ同期/);
  assert.doesNotMatch(app, /deviceManageSidebar|openSidebarDeviceManagement|refreshCryptoDeviceList/);
  assert.match(app, /runAutomaticCryptoMaintenance\(\{force:true\}\)/);
  assert.doesNotMatch(app, /registerDeviceAcrossAllChats|device-register-all-button|refreshCurrentDeviceRegistrationStatus/);
});
