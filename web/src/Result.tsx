import { useState } from "react";
import { sendFeedback, type Analysis, type DetectorStatus, type Severity, type Verdict } from "./api";

const VERDICT: Record<Verdict, { label: string; advice: string; ink: string; border: string }> = {
  likely_scam: {
    label: "Likely scam",
    advice: "Do not pay, share documents or reply until you verify the company yourself.",
    ink: "text-scam",
    border: "border-scam",
  },
  suspicious: {
    label: "Suspicious",
    advice: "Some things need checking. Confirm the offer on the company's official careers page.",
    ink: "text-warn",
    border: "border-warn",
  },
  looks_safe: {
    label: "No scam signs",
    advice: "Nothing we check looks wrong. Still, never pay money to get a job.",
    ink: "text-safe",
    border: "border-safe",
  },
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY: Record<Severity, { label: string; bar: string }> = {
  critical: { label: "Critical", bar: "bg-scam" },
  high: { label: "High", bar: "bg-scam/70" },
  medium: { label: "Medium", bar: "bg-warn" },
  low: { label: "Low", bar: "bg-rule" },
};

const DETECTOR_NAMES: Record<string, string> = {
  rules: "Scam patterns",
  text_model: "Writing style",
  company: "Company and sender",
  domain: "Websites and domains",
  headers: "Email authenticity",
};

const STATUS: Record<DetectorStatus, string> = {
  ok: "Checked",
  partial: "Partly checked",
  skipped: "Not needed for this input",
  unavailable: "Not available",
  timeout: "Took too long",
  error: "Could not run",
};

function MarkedText({ text, highlights }: { text: string; highlights: Analysis["highlights"] }) {
  const spans = [...highlights].sort((a, b) => a.start - b.start);
  const parts: React.ReactNode[] = [];
  let at = 0;
  for (const h of spans) {
    if (h.start < at) continue;
    parts.push(text.slice(at, h.start));
    parts.push(
      <mark
        key={h.start}
        className="rounded-sm bg-marker px-0.5 text-ink"
        style={{ opacity: 0.55 + 0.45 * h.weight }}
      >
        {text.slice(h.start, h.end)}
      </mark>,
    );
    at = h.end;
  }
  parts.push(text.slice(at));
  return <p className="max-h-72 overflow-y-auto whitespace-pre-wrap">{parts}</p>;
}

function Feedback({ analysisId, verdict }: { analysisId: string; verdict: Verdict }) {
  const [label, setLabel] = useState<"genuine" | "scam" | null>(null);
  const [comment, setComment] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [error, setError] = useState("");

  if (state === "sent") {
    return <p className="text-safe">Thanks. Your report helps improve the checker.</p>;
  }

  const wrongLabel = verdict === "looks_safe" ? "scam" : "genuine";
  async function send() {
    if (!label) return;
    setState("sending");
    try {
      await sendFeedback(analysisId, label, comment.trim());
      setState("sent");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setState("error");
    }
  }

  return (
    <div>
      <p className="font-bold">Is this result wrong?</p>
      {label === null ? (
        <button
          type="button"
          onClick={() => setLabel(wrongLabel)}
          className="mt-2 rounded-md border-2 border-ink px-4 py-2 text-sm font-bold hover:bg-paper"
        >
          {wrongLabel === "genuine" ? "It's a real offer" : "It's a scam"}
        </button>
      ) : (
        <div className="mt-2 space-y-3">
          <label htmlFor="fb-comment" className="block text-sm text-ink-soft">
            What did we get wrong? (optional, emails and phone numbers are removed)
          </label>
          <textarea
            id="fb-comment"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            maxLength={1000}
            rows={3}
            className="block w-full rounded border-2 border-rule p-2 focus:border-ink focus:outline-none"
          />
          <div className="flex gap-3">
            <button
              type="button"
              onClick={send}
              disabled={state === "sending"}
              className="rounded-md bg-ink px-4 py-2 text-sm font-bold text-sheet disabled:opacity-40"
            >
              {state === "sending" ? "Sending…" : "Send report"}
            </button>
            <button
              type="button"
              onClick={() => setLabel(null)}
              className="px-2 text-sm text-ink-soft underline underline-offset-2"
            >
              Cancel
            </button>
          </div>
          {state === "error" && (
            <p role="alert" className="text-sm text-scam">
              {error}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default function Result({ analysis: a }: { analysis: Analysis }) {
  const v = VERDICT[a.verdict];
  const flags = [...a.red_flags].sort(
    (x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity),
  );
  const detectors = Object.entries(a.detectors);

  return (
    <article className="rounded-md border-2 border-ink bg-sheet" aria-labelledby="verdict">
      <div className="flex flex-wrap items-center gap-6 border-b-2 border-ink p-6 sm:p-8">
        <div
          className={`stamp grid size-32 shrink-0 place-items-center rounded-full border-[5px] ${v.border} ${v.ink}`}
        >
          <div className="text-center leading-none">
            <span className="font-display block text-5xl font-extrabold">{a.score}</span>
            <span className="mt-1 block text-xs font-bold">out of 100</span>
          </div>
        </div>
        <div className="min-w-0 flex-1 basis-56">
          <h2 id="verdict" className={`font-display text-4xl font-extrabold ${v.ink}`}>
            {v.label}
          </h2>
          <p className="mt-2">{v.advice}</p>
          {a.confidence !== "high" && (
            <p className="mt-2 text-sm text-ink-soft">
              Some checks could not run, so this result is less certain.
            </p>
          )}
        </div>
      </div>

      {a.report_links.length > 0 && (
        <div className="border-b-2 border-ink bg-scam/5 px-6 py-4 sm:px-8">
          <p className="font-bold">Lost money or shared documents?</p>
          <p className="mt-1">
            Report it at{" "}
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noreferrer"
              className="font-bold underline underline-offset-2"
            >
              cybercrime.gov.in
            </a>{" "}
            or call the cyber fraud helpline{" "}
            <a href="tel:1930" className="font-bold underline underline-offset-2">
              1930
            </a>
            . Report quickly; it improves the chance of getting money back.
          </p>
        </div>
      )}

      <section className="p-6 sm:p-8" aria-labelledby="flags-heading">
        <h3 id="flags-heading" className="font-display text-xl font-bold">
          {flags.length === 0
            ? "No red flags found"
            : `${flags.length} red flag${flags.length === 1 ? "" : "s"}`}
        </h3>
        {flags.length > 0 && (
          <ul className="mt-4 space-y-4">
            {flags.map((f) => (
              <li key={`${f.id}-${f.evidence}`} className="flex gap-4">
                <span aria-hidden className={`w-1.5 shrink-0 rounded-full ${SEVERITY[f.severity].bar}`} />
                <div className="min-w-0">
                  <p>
                    <span className="mr-2 text-sm font-bold text-ink-soft">
                      {SEVERITY[f.severity].label}
                    </span>
                    {f.message}
                  </p>
                  {f.evidence && (
                    <p className="mt-1 border-l-2 border-rule pl-3 text-sm break-words text-ink-soft italic">
                      “{f.evidence}”
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {a.highlights.length > 0 && (
        <section className="border-t-2 border-rule p-6 sm:p-8" aria-labelledby="marked-heading">
          <h3 id="marked-heading" className="font-display text-xl font-bold">
            Phrases that sound like scams
          </h3>
          <p className="mt-1 mb-4 text-sm text-ink-soft">
            Highlighted by the text model. Stronger colour means a stronger scam signal.
          </p>
          <MarkedText text={a.analyzed_text} highlights={a.highlights} />
        </section>
      )}

      <section className="border-t-2 border-rule p-6 sm:p-8" aria-labelledby="checks-heading">
        <h3 id="checks-heading" className="font-display text-xl font-bold">
          What we checked
        </h3>
        <dl className="mt-3 grid gap-x-6 gap-y-2 sm:grid-cols-2">
          {detectors.map(([name, d]) => (
            <div key={name} className="flex justify-between gap-3 border-b border-rule py-1.5">
              <dt>{DETECTOR_NAMES[name] ?? name}</dt>
              <dd className={d.status === "ok" ? "text-safe" : "text-ink-soft"}>
                {STATUS[d.status] ?? d.status}
              </dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="border-t-2 border-rule p-6 sm:p-8">
        <Feedback analysisId={a.analysis_id} verdict={a.verdict} />
      </section>
    </article>
  );
}
