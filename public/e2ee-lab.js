window.addEventListener("DOMContentLoaded", () => {
  const button = document.querySelector("#start");
  const output = document.querySelector("#output");
  button.addEventListener("click", async () => {
    button.disabled = true;
    output.textContent = "SDKを初期化しています…";
    try {
      const userId = document.querySelector("#user-id").value.trim();
      const client = await SecureChatE2EE.openSecureChatE2EE(userId);
      output.textContent = JSON.stringify({
        status: "initialized",
        localClientCreated: Boolean(client),
        ...SecureChatE2EE.getSecureChatE2EEStatus()
      }, null, 2);
    } catch (error) {
      output.textContent = "初期化失敗: " + (error?.message || String(error));
    } finally {
      button.disabled = false;
    }
  });
});
