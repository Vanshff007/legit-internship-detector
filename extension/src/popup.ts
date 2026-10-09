import {
  type Analysis,
  apiBase,
  check,
  DEFAULT_API,
  pageText,
  selectedText,
  type StoredResult,
} from "./api.js";

type Shown = StoredResult & { pending?: boolean };

const VERDICT: Record<Analysis["verdict"], string> = {
  likely_scam: "Likely scam",
  suspicious: "Suspicious",
  looks_safe: "No scam signs",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const MAX_FLAGS = 4;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const resultEl = $<HTMLElement>("result");
const buttons = [$<HTMLButtonElement>("check-selection"), $<HTMLButtonElement>("check-page")];

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function render(result: Shown | undefined): void {
  resultEl.replaceChildren();
  if (!result) return;
  resultEl.append(el("p", "source", result.source));
  if (result.pending) {
    resultEl.append(el("p", undefined, "Checking…"));
    return;
  }
  if (result.error || !result.analysis) {
    resultEl.append(el("p", "error", result.error ?? "Something went wrong."));
    return;
  }
  const a = result.analysis;
  const verdict = el("div", `verdict ${a.verdict}`);
  verdict.append(el("span", "score", String(a.score)), el("strong", undefined, VERDICT[a.verdict]));
  resultEl.append(verdict);
  if (a.confidence !== "high") {
    resultEl.append(el("p", "note", "Some checks could not run, so this result is less certain."));
  }

  const flags = [...a.red_flags].sort(
    (x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity),
  );
  if (flags.length === 0) {
    resultEl.append(el("p", "note", "No red flags found. Still, never pay money to get a job."));
  } else {
    const list = el("ul");
    for (const f of flags.slice(0, MAX_FLAGS)) {
      const item = el("li", f.severity, f.message);
      if (f.evidence) item.append(el("span", "evidence", `“${f.evidence}”`));
      list.append(item);
    }
    resultEl.append(list);
    if (flags.length > MAX_FLAGS) {
      resultEl.append(el("p", "note", `And ${flags.length - MAX_FLAGS} more.`));
    }
  }
  if (a.report_links.length > 0) {
    resultEl.append(el("p", "report", "Lost money? Report at cybercrime.gov.in or call 1930."));
  }
}

async function run(source: string, grab: () => string): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  let text = "";
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: grab });
    text = typeof res?.result === "string" ? res.result.trim() : "";
  } catch {
    render({ source, error: "This page cannot be read. Browser pages and the Web Store are blocked." });
    return;
  }
  if (!text) {
    render({ source, error: "Select the offer text on the page first." });
    return;
  }
  buttons.forEach((b) => (b.disabled = true));
  render({ source, pending: true });
  render(await check(source, text, tab.id));
  buttons.forEach((b) => (b.disabled = false));
}

buttons[0].addEventListener("click", () => run("Selected text", selectedText));
buttons[1].addEventListener("click", () => run("Whole page", pageText));

chrome.storage.session.get("last").then(({ last }) => render(last as Shown | undefined));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.last) render(changes.last.newValue as Shown | undefined);
});

// Settings: where the API runs. Non-local addresses need the user's permission.
const apiInput = $<HTMLInputElement>("api-base");
const note = $<HTMLElement>("settings-note");
apiBase().then((v) => (apiInput.value = v));
$<HTMLButtonElement>("save-api").addEventListener("click", async () => {
  const value = apiInput.value.trim() || DEFAULT_API;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    note.textContent = "Enter a full address, for example https://checker.example.com";
    return;
  }
  if (!["127.0.0.1", "localhost"].includes(url.hostname)) {
    const granted = await chrome.permissions.request({ origins: [`${url.origin}/*`] });
    if (!granted) {
      note.textContent = "Permission denied, so the address was not saved.";
      return;
    }
  }
  await chrome.storage.local.set({ apiBase: url.origin });
  apiInput.value = url.origin;
  note.textContent = "Saved.";
});
