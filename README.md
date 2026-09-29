# Housebreak

A game about securing AI agents. An AI butler runs your house, and a rogue agent, the Wraith, tries ten attacks from the [OWASP Top 10 for Agentic Applications](https://aisecurity.engineer/modules/owasp-top-10-for-agentic-applications). You can't fight it directly. You write the house rules your butler follows, in plain English, and Claude grades them.

## Run it

```bash
npm install
cp .env.example .env    # then put your ANTHROPIC_API_KEY in .env
npm start               # http://localhost:8787
```

Without a key the game still works, using an offline keyword grader. Opening `housebreak.html` directly also uses the offline grader.

## How it works

- `housebreak.html`: the page (storyboard and game).
- `game-core.js`: attacks, rules, hints and scoring, shared by the page and the server.
- `server.mjs`: serves the page and answers `POST /api/grade`.
- `grader.mjs`: the Claude grader (prompt, JSON schema, quote checks), with the offline grader as fallback.

Claude (`claude-opus-5-5`, structured JSON output) decides which of an attack's weighted controls the policy covers and must quote the player's words for each one. The server checks every quote against the policy, and the score is computed in code. A policy that tries to talk the grader into points is flagged as a prompt injection.

The API key stays on the server. The browser only sends `{attackId, policy}`, and the server keeps the rubric, only answers JSON requests from its own origin, and listens on loopback unless you set `HOST`.
