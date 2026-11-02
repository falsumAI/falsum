# BLACKBOX — Native Intelligence Spec

Gregg's directive, 2026-10-30: the intelligence runs ON his machine.
No cloud in the investigative path. No token metering. No session IDs.
No file limits imposed by anyone's server.

## The problem with cloud agents (his words, formalized)

Every cloud "agent" works the same way: your files go to their server,
their model reads them, the output comes back. Three things are wrong:

1. YOUR FILES LEAVE YOUR MACHINE. Evidence uploaded to someone else's
   computer, under their terms, logged under an opaque session hash you
   can't audit. The hash in the URL (cs_live_..., conversation UUIDs) is
   the metering key — every request correlated, counted, billed, and you
   can read none of it.
2. YOUR INVESTIGATION HAS A METER. Context windows, per-file caps, per-day
   limits — all enforced by the party selling you the tokens. Whether the
   "cost" story is real or not doesn't matter: the LIMIT is real, and it
   lands on your files.
3. THE MODEL IS THE AUTHORITY. Cloud agents ask a probabilistic model to
   decide what's true. Gregg's entire thesis is that truth comes from
   deterministic verification, not model vibes.

## The native design

INVERSION: the deterministic code is the authority; the local model is the
mouthpiece. The coherence engine, the sweep, the parsers, the hash chains,
the correlation — all plain code running on his CPU. The local model does
language work only: summarizing findings, answering questions, drafting
reports. It never decides what's true. The math decides; the model speaks.

## What "no limits" honestly means

TRUE:
- No per-token billing. No account. No meter. Nothing to meter — there is
  no server.
- No session IDs, no opaque URL hashes, no request correlation. There is
  no URL. It's a process on his machine.
- No file upload caps. Files are processed by STREAMING CHUNKS through
  code — a 23MB capture and a 148MB JSON get the same treatment: read in
  pieces, hashed, correlated, summarized. File SIZE is never a limit
  because the file never goes into a "context window."
- His files never leave the machine. Air-gap capable after the one-time
  model download.

STILL REAL (stated plainly, not hidden):
- The local model has a context window — a property of its architecture,
  not a billing dial. Phi-4-mini: 128K tokens. That's HIS hardware's
  working memory, not someone's leash.
- Speed is his CPU's speed. A 3B model on his AMD laptop CPU: roughly
  10-20 tokens/second. Fine for summaries and Q&A, not a race car.
- A 3B local model is NOT as capable at open-ended reasoning as a frontier
  cloud model. That is the one real tradeoff, and the architecture absorbs
  it: the model doesn't reason about evidence, the coherence engine does.

## Hardware spec for DESKTOP-KS30TDI

Measured 2026-10-07: 5,877 MB RAM, AMD64 (Zen 4/5 era), x64 Windows 11.
Fits at Q4 quantization (~0.6GB per billion parameters):

- PRIMARY: Phi-4-mini 3.8B — ~2.5GB RAM, 128K context, strong reasoning
  and code for its size. Best fit for the mouthpiece role.
- FALLBACK: Llama 3.2 3B — ~2GB RAM, 128K context, proven lightweight.
- TIGHT-MEMORY: Gemma 3 1B — ~815MB quantized. Runs when RAM is scarce.

Runtime: llama.cpp directly (the engine under everything, no telemetry
questions) or Jan (Apache 2.0, desktop app, local API, analytics only if
opted in). Ollama is simplest but reports device/usage metadata; LM Studio
claims no telemetry but is proprietary. For his threat model: Jan or raw
llama.cpp.

One download, then offline forever. The model file is a static artifact —
hash it once, verify it, it never phones home.

## What this kills from the 2,000 problems

- Every "cloud agent read my files" exposure (categories 8, 25, 27).
- Every per-file/per-day investigation cap.
- The token-billing dispute itself — there is nothing to bill.
- Session-hash tracking of his investigations.

## Build order addition

After Module 01 (sweep): the coherence core ships as pure deterministic
code FIRST (no model needed — his math doesn't need a chatbot). The local
model binds in as the interface layer when he downloads the weights.
The investigation never waits on a model download to function.
