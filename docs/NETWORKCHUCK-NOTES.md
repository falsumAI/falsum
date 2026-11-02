# NetworkChuck Local AI Research Notes
# Studied per Gregg's order: "go watch all of network chucks youtube videos
# read all of them and take notes on all his videos around local ai or servers around ai locally"

## Videos Studied

### 1. "host ALL your AI locally" (youtube.com/watch?v=Wjrdr0NU4Sk)
**Key takeaways:**
- Built a dedicated AI server called "Terry" for his daughters
- Stack: Ollama (foundation) + Open WebUI (interface) + Stable Diffusion (images)
- Runs on Pop!_OS Linux, but works on Windows/Mac/Linux
- **Critical for Falsum:** "The setup can be done on a simple laptop; no need for high-end hardware"
- Privacy angle: "control over the AI usage for educational purposes"
- Open WebUI runs at localhost:8080, Docker container
- Integrates with Obsidian note-taking app (local AI + local notes)

**Applied to Falsum:**
- We use llama.cpp instead of Ollama (lighter, no Docker needed on Windows, single binary)
- Same localhost pattern: AI server at localhost:8080
- Same privacy principle: daughters → everyday user. If it's safe for his kids, it's safe for everyone.
- Falsum's "Terry" is the user's own PC — no separate server needed

### 2. "Run your own AI (but private)" (VMware sponsored)
**Key takeaways:**
- "Similar to ChatGPT, but entirely offline and private, right on your computer"
- Uses Llama 2 7B as example model
- Windows users: WSL (Windows Subsystem for Linux) for Ollama
- `ollama run llama2` — downloads and runs with one command
- Emphasizes: "survive a zombie apocalypse" (works with no internet)
- Connect knowledge base/documents for personalized queries

**Applied to Falsum:**
- Falsum skips WSL complexity — llama.cpp runs native on Windows
- Single-command model download via BITS (resumable, Windows-native)
- Knowledge base = the vault + lessons DB. The AI reads YOUR evidence, YOUR corrections.
- "Zombie apocalypse" = Falsum works with no internet after setup. This is the poison pill.

## NetworkChuck's Core Principles (extracted)

1. **Privacy is the product.** Not a feature. The reason to run locally.
2. **Control over cheating/data.** For his daughters (education), for Falsum users (surveillance).
3. **Any hardware works.** "Simple laptop" is enough. Falsum targets 6GB RAM machines.
4. **Localhost is the interface.** localhost:11434 (Ollama), localhost:8080 (WebUI). Falsum: localhost:8080 (llama.cpp).
5. **One command to start.** `ollama run` → Falsum: double-click Start-AI.bat.

## What Falsum Does Differently (the 20000x twist)

NetworkChuck teaches you to SET UP local AI. Falsum SHIPS it:
- No Docker. No WSL. No Linux. One PowerShell installer on Windows.
- The AI isn't a separate tool — it's INTEGRATED. It narrates security findings, learns from corrections, checks the vault.
- NetworkChuck's AI answers questions. Falsum's AI PROTECTS YOU. Different job.
- His math (coherence core) scores the AI's own outputs for truthfulness. No cloud AI does this.

## The Altman Challenge (from Gregg)

"Sam Altman said local AI is shit. Cloud AI is shit and you are going to prove it."

NetworkChuck proved local AI WORKS. Falsum proves local AI WINS:
- Cloud: $20/month, your data on their servers, can refuse, can be censored
- Falsum: $0, your data on your disk, never refuses, can't be remotely altered
- The model doesn't need to be smarter than GPT-4. It needs to be TRUSTWORTHY.
- Deterministic code decides truth. The model renders it in plain language.
- That's the job. Cloud can't do it because cloud can't be trusted.
