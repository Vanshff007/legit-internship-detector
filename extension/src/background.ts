import { check } from "./api.js";

const MENU_ID = "check-selection";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Check with Legit Internship Detector",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !info.selectionText) return;
  await chrome.storage.session.set({ last: { source: "Selected text", pending: true } });
  // Opening the popup needs the click's user gesture, so do it before the request.
  chrome.action.openPopup?.().catch(() => undefined);
  await check("Selected text", info.selectionText, tab?.id);
});
