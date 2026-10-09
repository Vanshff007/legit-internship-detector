export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict = "looks_safe" | "suspicious" | "likely_scam";
export type DetectorStatus = "ok" | "partial" | "skipped" | "unavailable" | "timeout" | "error";

export interface RedFlag {
  id: string;
  detector: string;
  severity: Severity;
  message: string;
  evidence: string;
}

export interface Highlight {
  start: number;
  end: number;
  weight: number;
}

export interface Analysis {
  analysis_id: string;
  score: number;
  verdict: Verdict;
  confidence: string;
  red_flags: RedFlag[];
  highlights: Highlight[];
  detectors: Record<string, { status: DetectorStatus }>;
  report_links: string[];
  model_version: string | null;
  analyzed_text: string;
}

export type OfferInput =
  | { kind: "text"; text: string }
  | { kind: "url"; url: string }
  | { kind: "file"; file: File };

async function errorMessage(r: Response): Promise<string> {
  if (r.status === 429) return "Too many checks in a minute. Wait a moment and try again.";
  try {
    const body = await r.json();
    if (typeof body.detail === "string") return body.detail;
  } catch {
    // fall through
  }
  return `The server could not check this offer (error ${r.status}).`;
}

export async function analyze(input: OfferInput): Promise<Analysis> {
  let init: RequestInit;
  if (input.kind === "file") {
    const form = new FormData();
    form.append("file", input.file);
    init = { method: "POST", body: form };
  } else {
    const body = input.kind === "text" ? { text: input.text } : { url: input.url };
    init = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    };
  }
  let r: Response;
  try {
    r = await fetch("/api/v1/analyze", init);
  } catch {
    throw new Error("Could not reach the checker. Make sure the server is running.");
  }
  if (!r.ok) throw new Error(await errorMessage(r));
  return r.json();
}

export async function sendFeedback(
  analysisId: string,
  label: "genuine" | "scam",
  comment: string,
): Promise<void> {
  const r = await fetch("/api/v1/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analysis_id: analysisId, label, comment: comment || null }),
  });
  if (!r.ok) throw new Error(await errorMessage(r));
}
