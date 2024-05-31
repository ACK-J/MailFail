browser.runtime.onMessage.addListener((message) => {
  if (message.action === "updateBadge") {
    let getStoredTab = parseInt(localStorage.getItem("tabID"), 10);
    // Update the badge text with the provided number for the current tab
    browser.browserAction.setBadgeText({ tabId: getStoredTab, text: message.number.toString() });
  }
});

function onCreated(windowInfo) {
  browser.windows.update(windowInfo.id, {
    height: 850,
    width: 400,
  });
}

browser.browserAction.onClicked.addListener(async function(tab) {
  let pane = browser.windows.create({
    url: "popup.html",
    type: "popup",
  });
  pane.then(onCreated);
  // Store the URL of the current tab in storage
  await localStorage.clear();
  localStorage.setItem("url", tab.url);
  localStorage.setItem("tabID", tab.id);
});

