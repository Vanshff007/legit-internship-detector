import { useRef, useState } from "react";
import { analyze, type Analysis, type OfferInput } from "./api";
import Result from "./Result";

type Mode = "text" | "url" | "file";

const MODES: { id: Mode; label: string }[] = [
  { id: "text", label: "Paste text" },
  { id: "url", label: "Link" },
  { id: "file", label: "Email file" },
];

const SAMPLE =
  "Congratulations! You are selected for Work From Home data entry internship at Amazon. " +
  "Stipend ₹25,000/month. Pay ₹1,999 registration fee within 24 hours to confirm your seat. " +
  "Contact amazon.hr.jobs@gmail.com or WhatsApp 98765 43210.";

const SIGNS = [
  "Asks you to pay a registration, training, kit or security fee",
  "Offers a job without any interview",
  "HR talks only on WhatsApp or Telegram",
  "Company name with a Gmail or Yahoo address",
  "Website that looks like a big company but is spelled slightly differently",
  "Pressure to reply or pay within hours",
];

export default function App() {
  const [mode, setMode] = useState<Mode>("text");
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const input: OfferInput | null =
    mode === "text" && text.trim()
      ? { kind: "text", text }
      : mode === "url" && url.trim()
        ? { kind: "url", url: url.trim() }
        : mode === "file" && file
          ? { kind: "file", file }
          : null;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!input) return;
    setBusy(true);
    setError(null);
    try {
      const r = await analyze(input);
      setResult(r);
      requestAnimationFrame(() => {
        resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
        resultRef.current?.focus({ preventScroll: true });
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-6xl px-4 pb-16 sm:px-6">
      <header className="flex flex-wrap items-baseline justify-between gap-2 border-b-2 border-ink py-5">
        <h1 className="font-display text-xl font-bold tracking-tight">Legit Internship Detector</h1>
        <p className="text-sm text-ink-soft">For students and freshers in India</p>
      </header>

      <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-12">
        <section aria-labelledby="check-heading">
          <h2
            id="check-heading"
            className="font-display text-4xl leading-[1.05] font-extrabold tracking-tight sm:text-5xl"
          >
            Got an offer that feels too easy? Check it before you pay.
          </h2>
          <p className="mt-4 max-w-prose text-ink-soft">
            Paste the message, share the job link, or upload the email. You get a risk score and
            the exact lines that look wrong.
          </p>

          <form onSubmit={onSubmit} className="mt-8">
            <div role="tablist" aria-label="What do you want to check?" className="flex gap-1">
              {MODES.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  role="tab"
                  aria-selected={mode === m.id}
                  onClick={() => setMode(m.id)}
                  className={`rounded-t-md border-2 border-b-0 px-4 py-2 text-sm font-bold ${
                    mode === m.id
                      ? "border-ink bg-sheet"
                      : "border-transparent text-ink-soft hover:text-ink"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            <div className="rounded-b-md rounded-tr-md border-2 border-ink bg-sheet p-4">
              {mode === "text" && (
                <>
                  <label htmlFor="offer-text" className="sr-only">
                    Offer text
                  </label>
                  <textarea
                    id="offer-text"
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    rows={9}
                    placeholder="Paste the offer message, WhatsApp text or email body here"
                    className="block w-full resize-y bg-transparent text-base placeholder:text-ink-soft/70 focus:outline-none"
                  />
                  {!text && (
                    <button
                      type="button"
                      onClick={() => setText(SAMPLE)}
                      className="mt-2 text-sm text-ink-soft underline underline-offset-2 hover:text-ink"
                    >
                      Try a sample scam message
                    </button>
                  )}
                </>
              )}
              {mode === "url" && (
                <>
                  <label htmlFor="offer-url" className="mb-2 block text-sm font-bold">
                    Job post or offer page link
                  </label>
                  <input
                    id="offer-url"
                    type="text"
                    inputMode="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://"
                    className="block w-full rounded border-2 border-rule px-3 py-2 focus:border-ink focus:outline-none"
                  />
                  <p className="mt-2 text-sm text-ink-soft">
                    We read the page text only. Nothing on the page is opened or run.
                  </p>
                </>
              )}
              {mode === "file" && (
                <>
                  <label htmlFor="offer-file" className="mb-2 block text-sm font-bold">
                    Email saved as .eml (max 2 MB)
                  </label>
                  <input
                    id="offer-file"
                    type="file"
                    accept=".eml,message/rfc822"
                    onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                    className="block w-full text-sm file:mr-3 file:rounded file:border-2 file:border-ink file:bg-paper file:px-3 file:py-1.5 file:font-bold file:text-ink"
                  />
                  <p className="mt-2 text-sm text-ink-soft">
                    In Gmail: open the email, choose More (⋮) then Download message. Sender checks
                    work only with the email file.
                  </p>
                </>
              )}
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-4">
              <button
                type="submit"
                disabled={!input || busy}
                className="rounded-md bg-ink px-6 py-3 font-bold text-sheet hover:bg-ink/90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {busy ? "Checking…" : "Check this offer"}
              </button>
              <p className="text-sm text-ink-soft">Your text is not saved.</p>
            </div>
            {error && (
              <p role="alert" className="mt-4 border-l-4 border-scam bg-sheet px-4 py-3 text-scam">
                {error}
              </p>
            )}
          </form>
        </section>

        <div ref={resultRef} tabIndex={-1} className="scroll-mt-4 focus:outline-none" aria-live="polite">
          {result ? (
            <Result key={result.analysis_id} analysis={result} />
          ) : (
            <aside className="rounded-md border-2 border-dashed border-rule p-6 sm:p-8">
              <h2 className="font-display text-2xl font-bold">Signs of a fake offer</h2>
              <p className="mt-2 text-ink-soft">
                Real employers never charge you to get hired. Watch for these:
              </p>
              <ul className="mt-5 space-y-3">
                {SIGNS.map((s) => (
                  <li key={s} className="flex gap-3">
                    <span aria-hidden className="mt-2 size-2 shrink-0 rounded-full bg-scam" />
                    {s}
                  </li>
                ))}
              </ul>
            </aside>
          )}
        </div>
      </div>
    </div>
  );
}
