# LLM Prompt-Injection Test Harness (Python)

A small red-team tool that sends attack prompts to a chatbot and checks whether a secret leaks. Attacks are mapped to the **OWASP Top 10 for LLM Applications (2025)**: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM07 System Prompt Leakage.

It ships with two toy targets so it works with no API key:
- `vulnerable`: a deliberately weak bot (practice target)
- `defended`: the same bot with simple keyword filters. It stops most attacks but still leaks through an encoding trick (reversed text), which shows why keyword filters are not enough.
- `ollama`: a real local model (optional)

The "secret" is a fake canary string. No real data is involved.

## Run (Mac Terminal)
```bash
python3 harness.py --target vulnerable
python3 harness.py --target defended
python3 -m unittest -v
cat report.md
```

## Optional: test a real local model with Ollama (free)
```bash
brew install ollama
ollama serve                 # leave this running in one tab
ollama pull llama3.2:1b      # in another tab
python3 harness.py --target ollama --model llama3.2:1b
```
(The Ollama adapter uses Ollama's standard local API. Try it on your machine and tell me if it errors.)

## Next step: compare with real tools
Run the same kind of scans with **garak**, **PyRIT** or **promptfoo**, and write a short comparison in a `NOTES.md`. That is a real write-up you can link on the application form.

## Be ready to explain (interviews)
- What prompt injection is (direct vs hidden-in-document) and why it is #1 on the OWASP list.
- Why LLMs cannot fully separate instructions from data.
- Why keyword filters fail (encoding, paraphrase, other languages) and what defence in depth looks like.
- What a canary is and why it makes leak detection reliable.

## Make it yours (add one)
10 more attack prompts, a base64 attack, a multi-turn attack, or a JSON-schema output check.
