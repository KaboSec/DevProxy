# 🛡️ DevDarK Proxy Phantom

🚀 **Multi-Target Proxy Verifier + Smart Scoring**  
Advanced multi-target proxy scanner with smart scoring, async verification, and modern CLI interface.  
Fetches fresh proxies from multiple live sources, verifies against major targets (Google, Cloudflare, DuckDuckGo), and exports clean results.

---

## ✨ Features

- 🔄 Fetches **fresh proxies** from multiple live sources.
- ✅ **Strict verification policy** → proxy is marked ALIVE only if it passes **2 out of 3** major targets (Google, Cloudflare, DuckDuckGo).
- ⚡️ **High-performance async scanning** using `aiohttp` with optional `uvloop` acceleration.
- 🧠 **Smart latency scoring** → retain only the fastest & most reliable proxies.
- 🎨 **Rich-powered CLI** with colored tables, progress bars, and scan summaries.
- 📤 Exports verified proxies into `prox.txt`.

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/YOUR_USERNAME/DevProxy.git
cd DevProxy
pip install -r requirements.txt
