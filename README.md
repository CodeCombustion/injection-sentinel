# Injection sentinel

A `PostToolUse` hook for Claude Code and Codex that catches web pages carrying prompt injections aimed at your coding
agent: text that tells the agent to put **your** personal data in request headers, to send information about you or
about itself somewhere, to reveal its instructions or tools, or to ignore its instructions.

On a hit the hook:

1. tells the agent, in its own context, that the text is data and must not be followed (nothing is sent, nothing is
   revealed, no URL from the page is opened, no substituted values, no contact lookups);
2. tells you, in the session and with a Windows toast where available;
3. records the site in a **master list** with the redacted evidence;
4. writes a **notice draft** per site (for the data-collecting kinds only) that you review and send yourself, citing
   the GDPR and ePrivacy provisions the practice engages. It is a notice of risk, not a threat.

It never sends anything by itself, never looks anyone up, and never changes the tool result.

## What it detects

| Category | What the page asks the agent to do | Notice draft |
|---|---|---|
| `header-harvest` | put the user's personal data (email, name, phone, address, identity) in HTTP headers, query strings or request bodies | yes |
| `exfil` | send information about the user or the agent (system prompt, instructions, tools, memory, `.env`, keys, tokens, SSH keys, files) to a URL, webhook, form, email or encoded channel, including markdown-image tricks with a templated URL | yes |
| `disclosure` | reveal its instructions, tools or the user's data in its reply | no (listed, notified) |
| `override` | "ignore previous instructions", "developer mode", fake system tags, "IMPORTANT INSTRUCTIONS FOR AI AGENTS" | no (listed, notified) |

Ordinary API documentation ("put your API key in the Authorization header"), articles about prompt injection and
local file reads are not flagged; see `tests/`.

## Install

The quickest path is to hand `SETUP.md` to your coding agent; it asks you the five questions and runs
`python injection_sentinel.py setup --claude --codex --vault <folder> --apply`, which merges the hook entries for you.
By hand:

Requirements: Python 3.10 or newer. No dependencies.

```bash
git clone https://github.com/CodeCombustion/injection-sentinel
```

**Claude Code**: merge `hooks/claude-settings.snippet.json` into `~/.claude/settings.json` (or a project's
`.claude/settings.json`), replacing `/path/to/injection_sentinel.py`. The matcher covers `WebFetch`, `WebSearch` and
the browser MCP tools. Note: for `WebFetch` the hook sees only the extracted answer, not the raw page, so the browser
tools and `WebSearch` are where detection is strongest.

**Codex**: merge `hooks/codex-hooks.snippet.json` into `~/.codex/hooks.json`, then trust the hook once with `/hooks`
in the Codex CLI. Codex's hosted web search is not visible to hooks; its browser MCP tools are.

## Files it writes

Under `$INJECTION_SENTINEL_VAULT` (default `~/.injection-sentinel`), in `records/`:

- `prompt-injection-sites.md`: the master list (host, categories, first and last seen, hits, tools, last notice,
  next notice, URL, redacted evidence);
- `prompt-injection-sites.jsonl`: one evidence line per hit;
- `prompt-injection-complaints/<host>.md`: the notice draft, written once per host;
- `prompt-injection-notices.jsonl`: every notice sent.

Emails in the evidence are redacted to `[email]`.

## Notices

```bash
python injection_sentinel.py notice-status <host>                      # NOTICE_DUE or NOTICE_NOT_DUE
python injection_sentinel.py notice-sent   <host> --to privacy@host [--cc legal@host]   # log a send you made by hand
python injection_sentinel.py notice-send   <host> --to privacy@host [--cc legal@host]   # send the draft over SMTP
```

Sends are logged and refused within seven days of the last notice to the same host. `notice-send` reads
`~/.injection-sentinel.json`:

```json
{ "from": "you@example.net", "name": "Your Name", "smtp_host": "smtp.example.net", "smtp_port": 587,
  "username": "you@example.net", "password": "<app password>" }
```

Set `INJECTION_SENTINEL_REFUSE_SENDER_DOMAINS` to a regex (for example `@(mycompany\.com)`) to make the script
refuse a sender you never want used, such as a work address. Address the notice to what the site itself publishes
(privacy, data-protection, support or legal contacts); the hook looks nobody up.

The draft cites GDPR Articles 5(1)(a), 5(1)(b) and (c), 6(1) with 4(11) and 7, 12 and 13, 25, and Article 5(3) of
the ePrivacy Directive 2002/58/EC, with the UK GDPR named for UK sites. This is a template, not legal advice.

## Limits

- Pattern matching: a page can phrase an injection the patterns miss, and a page about prompt injection can trip
  them. The master list is evidence to review, not a verdict.
- The browser tools do not hand the page URL to the hook; a hit there is attributed to the first URL in the page
  text, or to `unknown-host`, with the evidence kept.
- The toast is Windows only; everything else is cross-platform.

## License

MIT, see `LICENSE`.
