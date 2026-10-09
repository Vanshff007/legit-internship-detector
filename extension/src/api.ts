export interface RedFlag {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  evidence: string;
}

export interface Analysis {
  analysis_id: string;
  score: number;
  verdict: "looks_safe" | "suspicious" | "likely_scam";
  confidence: string;
  red_flags: RedFlag[];
  report_links: string[];
}

export interface StoredResult {
  source: string; // what was checked, for the popup heading
  analysis?: Analysis;
  error?: string;
}

export const DEFAULT_API = "http://127.0.0.1:8000";
const MAX_TEXT = 20_000;

export async function apiBase(): Promise<string> {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (typeof apiBase === "string" && apiBase) || DEFAULT_API;
}

export async function analyzeText(text: string): Promise<Analysis> {
  const base = await apiBase();
  let r: Response;
  try {
    r = await fetch(`${base}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text.slice(0, MAX_TEXT) }),
    });
  } catch {
    throw new Error(`Could not reach the checker at ${base}. Is the server running?`);
  }
  if (!r.ok) {
    if (r.status === 429) throw new Error("Too many checks in a minute. Try again shortly.");
    const body = await r.json().catch(() => null);
    throw new Error(body?.detail ?? `The checker returned error ${r.status}.`);
  }
  return r.json();
}

const BADGE: Record<Analysis["verdict"], string> = {
  likely_scam: "#b4231b",
  suspicious: "#a6620b",
  looks_safe: "#1d7a4f",
};

export async function showResult(result: StoredResult, tabId?: number): Promise<void> {
  await chrome.storage.session.set({ last: result });
  const a = result.analysis;
  await chrome.action.setBadgeText({ text: a ? String(a.score) : "!", tabId });
  await chrome.action.setBadgeBackgroundColor({
    color: a ? BADGE[a.verdict] : "#4a5878",
    tabId,
  });
}

export async function check(source: string, text: string, tabId?: number): Promise<StoredResult> {
  let result: StoredResult;
  try {
    result = { source, analysis: await analyzeText(text) };
  } catch (e) {
    result = { source, error: e instanceof Error ? e.message : String(e) };
  }
  await showResult(result, tabId);
  return result;
}

/** Visible text of the page, with its address first so the page's domain is checked too. */
export function pageText(): string {
  return `Page: ${location.href}\n\n${document.body?.innerText ?? ""}`;
}

export function selectedText(): string {
  return window.getSelection()?.toString() ?? "";
}
