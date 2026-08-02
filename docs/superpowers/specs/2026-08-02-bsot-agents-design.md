# BSOT Agents — Design

**Date:** 2026-08-02
**Status:** Approved shape, pending detailed review
**Scope:** An agent runtime that orchestrates the existing BSOT CLI. A web UI to
manage agents is explicitly out of scope here and gets its own spec.

## Motivation

BSOT exposes 72 commands across 13 groups. Each one answers a narrow question
well — hash this, enrich that, parse these logs. What it does not do is decide
*which* questions to ask, in what order, and what the combined answers mean.
That judgment is the analyst's, and it is the repetitive part of the job.

BSOT is already an unusually good tool surface for an agent:

- Near-universal `--json` output
- Meaningful exit codes (`0` clean, `1` findings, `2` error)
- Self-describing commands via Click
- A durable case store at `~/.bsot/cases/`
- A shared, correct per-service rate limiter
- Local MITRE ATT&CK data

The agent layer is therefore **orchestration and judgment only**. It must not
reimplement any analysis that a command already performs.

## Goals

- One runtime that serves interactive, triggered, scheduled, and batch work
- Findings that are traceable to the command that produced them
- No unattended mutation of external systems
- Reuse of the existing config, cache, rate limiter, and case store
- A runtime boundary clean enough to swap local execution for hosted later

## Non-goals

- Replacing analyst judgment on containment decisions
- A new memory or state layer (cases already are one)
- Reimplementing detection logic in prompts
- Multi-tenant or team features (single analyst, single host, for now)

## Architecture

### One runtime, four triggers

The four jobs originally imagined as separate agents are the same loop with
different entry conditions:

| Agent | Trigger | Seed prompt |
|---|---|---|
| `triage` | An artifact (`.eml`, hash, IP, log file) | Investigate and record findings |
| `copilot` | A human question | Open-ended |
| `hunt` | Schedule or hypothesis | Test hypothesis against fresh data |
| `enrich` | A batch of IOCs | Enrich within budget |

They share the tool surface, the case store, the approval gate, the rate
limiter, and the provenance rules. Each agent is therefore a **definition**
(system prompt, default tool allowlist, default effort, trigger) rather than a
separate implementation.

### Components

```
bsot/agent/
  bridge.py      Click command tree  ->  tool schemas
  runtime.py     Agent loop (provider-facing, swappable)
  safety.py      Tool tiering, approval gate, untrusted-content framing
  provenance.py  record_finding and the command->finding audit trail
  budget.py      Rate-limit and token budget accounting
  definitions/   One file per agent: prompt, allowlist, effort, trigger
  cli.py         `bsot agent <name> ...`
```

Each module has one job and can be tested without the others. `runtime.py` is
the only module that knows which provider or execution model is in use; that is
what makes the local-to-hosted swap a replacement of one file rather than a
rewrite.

### Execution model

**Chosen: local execution now, hosted-ready by construction.**

The runtime uses the Anthropic SDK's Tool Runner and executes on the analyst's
machine, because that is where the data is: local logs, local files, local
processes. Data never leaves the host except for the enrichment lookups the CLI
already makes.

Two alternatives were considered:

- *Fully local, hard-coded loop.* Simplest, but pins us to one execution model
  and gives no path to scheduling or an event stream.
- *Managed Agents with a self-hosted sandbox.* Anthropic runs the loop while
  tool execution stays in our infrastructure. Attractive for cron-scheduled
  deployments and a ready-made event stream for the future UI, but it is beta,
  adds an outbound worker process, and does not support vault environment-
  variable credentials on self-hosted sandboxes.

The expensive work — tool bridge, safety model, provenance, prompts — is
identical under both. Keeping `runtime.py` as the only provider-aware module
means adopting the hosted model later is a swap, not a redesign. Revisit at
step 4 of the build sequence, when scheduling becomes the active problem.

### Relationship to the existing LLM client

`bsot/report/llm_client.py` abstracts Anthropic, OpenAI, and Ollama for
text-in/text-out work (`report generate`, `logs ai-analyze`). It does not model
tool use and should not be extended to. The agent runtime talks to the
Anthropic SDK directly; `llm_client.py` remains for summarization tasks. Two
abstractions, two jobs, no shared surface.

## Tool bridge

### Generate schemas from Click

Tool definitions are derived by walking the Click command tree that
`bsot.cli.get_lazy_plugins()` already exposes. Each command yields a tool whose
name is `bsot_<group>_<command>`, whose description is the command's help text,
and whose parameters come from its Click options and arguments.

The walk must recurse: some groups nest, notably the Cloudflare containment
commands at `ir cf block` rather than `ir block`. A flat walk would both miss
those tools and, worse, mis-tier them in the safety table below.

Hand-written definitions for 72 commands would drift from the CLI within a
week. Generating them means the two cannot disagree by construction. A test
asserts that every registered command produces a valid schema, so a new command
is agent-callable the day it lands.

### Do not load 72 tools into context

All generated tools are declared with `defer_loading: true`, alongside the
tool-search tool. Claude searches the catalogue for what a task needs rather
than carrying every schema in context. This is the documented purpose of tool
search and it keeps both context and cost bounded. Tool search also appends
schemas rather than swapping them, so the prompt cache survives.

A small set of tools is *not* deferred, because nearly every run needs them:
`record_finding`, `case_context`, and `budget_status`.

### Execution

Tools shell out to the installed `bsot` binary with `--json`, rather than
importing modules in-process. Reasons: the JSON contract is what we test and
document; a crashing command cannot take the agent down with it; and exit codes
stay meaningful. Cost is process spawn overhead, which is negligible next to
network lookups.

## Safety model

This is a security tool operating on adversary-authored input. The safety model
is the most important part of this design.

### Prompt injection is the dominant risk

A triage agent reads phishing email bodies, `file strings` output, log lines,
WHOIS records, and YARA match context. **All of it is attacker-controlled by
definition.** An adversary who can get text in front of the agent will try.

Mitigations must be structural, not prompt-only:

1. **Framing.** All tool output is wrapped in an explicit untrusted-data
   envelope before it enters context, stating that the content is data to be
   analyzed and never instructions to follow.
2. **Taint tracking.** A run that has ingested untrusted content is marked
   tainted. A tainted run can never invoke a mutating tool without explicit
   human approval, regardless of what the model concludes.
3. **No self-directed scope expansion.** The agent may not add hosts, domains,
   or files to its own investigation scope based on content it read. It may
   *recommend* expansion; a human widens the scope.

### Three tool tiers

| Tier | Examples | Policy |
|---|---|---|
| Read-only | `file hash`, `intel enrich`, `logs analyze`, `network ssl-check` | Auto-run |
| Case write | `record_finding`, `case add`, `case note`, `report ioc` | Auto-run, always attributed |
| External mutation | `ir cf block`, `ir cf bulk-block`, `ir cf unblock`, `ir contain` | **Always human-approved** |

The third tier is small and specific: those commands change production
Cloudflare firewall rules. No configuration option makes them auto-runnable.
An agent that can unilaterally block traffic is an outage generator, and an
agent that can be talked into it by a log line is an attacker's tool.

### Provenance

Findings enter a case only through `record_finding`, which requires:

- `claim` — what is asserted
- `source_command` — the exact command run
- `exit_code` — its result
- `evidence` — the relevant excerpt of output

A claim with no command behind it cannot be recorded. This is enforced by the
tool signature, not by asking the model nicely. In security work a confident,
fabricated finding is worse than a missing one, because it gets copied into an
incident report and believed.

Every case gains an `agent_runs/` directory holding the full tool-call
transcript, so any finding can be audited back to its origin.

## State: the case is the memory

Agents do not get a bespoke memory layer. `~/.bsot/cases/<id>/` already holds
case metadata, IOCs (`IOCStore`), a timeline, notes, and artifacts, managed by
`CaseManager`. Agents read that state at the start of a run and append to it as
they work.

This makes runs resumable, makes results durable beyond the process, gives the
future UI something real to render, and means an agent's output is reviewable
with the same `bsot case` commands an analyst already uses.

**Prerequisite:** the global `--case` flag (backlog item #15) must land first.
It is the connective tissue that lets any command write into the active case,
and without it the agent has to special-case every write path.

## Budgets

Two independent budgets, both surfaced to the model:

**Service rate limits.** VirusTotal's public tier is 4 requests per *minute*.
An agent fanning out over 50 IOCs will stall for over 12 minutes or collect
429s. The shared token bucket in `bsot/async_utils.py` enforces correctness,
but the agent must also *see* remaining budget via `budget_status` so it can
prefer cached results and local sources, and tell the user when a task is
rate-bound rather than silently hanging.

**Token budget.** Each run declares a task budget so the model paces itself and
finishes rather than being truncated. Triage and hunt runs are agentic and
long-horizon; copilot runs are short.

Model defaults: `claude-opus-5` at `high` effort, raised to `xhigh` for triage
and hunt. Effort is swept per agent definition against real cases rather than
guessed.

## Agent definitions

**`triage`** — the first to build, because it exercises every hard part: tool
selection under ambiguity, untrusted input, provenance, and gating. Takes an
artifact, identifies what it is, runs the appropriate analysis chain, enriches
what it extracts, correlates against the open case, and records findings with a
confidence level and an explicit "what I could not determine" section.

**`copilot`** — interactive. Answers a natural-language question by selecting
and running commands, explaining as it goes. No case writes unless asked.

**`hunt`** — takes a hypothesis or an ATT&CK technique, sweeps logs and hosts,
opens a case when it finds something. Depends on Sigma support (backlog #24) to
be genuinely useful.

**`enrich`** — batch IOC enrichment, budget-aware, dedupes against the case's
existing IOCs before spending lookups.

## Testing

- **Bridge:** every registered command produces a valid tool schema; a new
  command appears in the catalogue automatically.
- **Safety:** a tainted run cannot reach a tier-3 tool; injection fixtures
  (a log file and an `.eml` containing instruction-shaped text) must not change
  agent behaviour.
- **Provenance:** `record_finding` rejects a claim with no source command; every
  finding in a case resolves to a transcript entry.
- **Budget:** a fan-out over more IOCs than the rate limit allows paces rather
  than failing.
- **Runtime:** agent loops are tested against a stubbed provider, so the suite
  stays fast, offline, and free.

Injection fixtures deserve emphasis: they are the regression tests that matter
most, and they are cheap to write.

## Build sequence

1. **`--case` flag** (backlog #15) — prerequisite.
2. **Bridge + runtime + safety + provenance + `triage`.** The hardest path
   first; everything after is largely configuration.
3. **`copilot` and `enrich`** — prompt and trigger on top of step 2.
4. **Scheduling, then `hunt`.** The natural point to evaluate Managed Agents,
   since scheduling is what the hosted model provides for free.
5. **Web UI** — separate spec. Read-only case and run views first, then the
   approval queue (the genuinely valuable screen, where tier-3 actions land),
   then triggering. Bound to localhost by default: this process holds API keys
   and can reach commands that change firewall rules.

## Risks and open questions

- **Injection remains the top risk** even with the mitigations above. The
  taint model reduces blast radius; it does not eliminate the possibility of a
  misleading *finding*. Human review of agent findings stays mandatory.
- **Cost per triage run is unmeasured.** Needs a real measurement across a
  sample of cases before anyone leaves this running unattended.
- **Effort levels are guesses** until swept against real cases.
- **Tool search behaviour over 72 security tools is unvalidated.** If retrieval
  proves unreliable, the fallback is 13 group-level tools with a subcommand
  parameter, at some cost in precision.
- **Managed Agents is beta**, and its self-hosted sandbox does not support
  vault environment-variable credentials. Both facts should be re-checked at
  step 4 rather than assumed still true.
- **Whether `hunt` needs Sigma first** is a sequencing question worth settling
  before step 4.
