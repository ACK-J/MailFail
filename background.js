browser.runtime.onMessage.addListener((message) => {
  if (message.action === "updateBadge") {
    // Update the badge text with the provided number
    browser.browserAction.setBadgeText({ text: message.number.toString() });
  }
});
