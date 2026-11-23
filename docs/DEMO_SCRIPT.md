# Demo video script (target 4:30, hard limit 5:00)

**Setup before recording**
- `.env` holds both keys, and `trailguard setup` has run.
- One `meko` run (epoch 1) is finished and its patterns are learned but **not yet approved**.
- A `trailguard bench` against Meko Cloud has finished, so the Results tab is populated.
- Browser tab 1: dashboard at `http://127.0.0.1:8000`. Tab 2: the Meko portal open on `trailguard-signals` > Conversations.
- Live tab settings: Speed "Demo", 600 events.

| Time | Screen | Say (roughly) |
|---|---|---|
| 0:00–0:25 | Dashboard, Live tab, idle | "Account takeover never happens in one step. A support call moves a phone number, a password reset, a new device, a new payee, then the money's gone. Each step lands with a different team, and each one looks harmless alone. TrailGuard gives those teams' agents one shared memory in Meko." |
| 0:25–0:45 | Point at the lanes | "Four channel agents, each seeing only its own stream: login, device, recovery and support, payments. A Sentinel decides the risky moments. Everything they share lives in two Meko datapacks: raw signals, and confirmed attacker patterns with our fraud playbooks." |
| 0:45–1:50 | Context "Shared through Meko", epoch 1, Start run. Let it play. | "Each dot is a signal an agent wrote to Meko with `memory_add`. Each thread is another agent reading it back with `memory_search` before acting. Watch this one: the device agent sees one fingerprint on a third account. When the next login arrives on another account, the login agent already knows, and the Sentinel blocks it. The mule ring is stopped at its first step, not at the transfer." Point at the attack tracker: "stopped 3 steps before takeover." |
| 1:50–2:40 | Click a Block in Latest decisions → Explain tab | "Anyone should be able to answer why in two minutes. Plain English: what was attempted, which agent saw what and when, with the Meko memory each came from, the policy section, and what happened next. This is built from the trace, not written afterwards." Switch to tab 2: "And in Meko itself, the same decision is a conversation turn with reasoning, a plan and token usage, the Decision trace view, with the full execution trace behind it." |
| 2:40–3:20 | Learnings tab | "After the run, confirmed attacks become candidate patterns. The Curator keeps only signals genuine customers almost never show, plus the attacker's infrastructure. They're Meko learnings, private until an analyst approves. Approve." Click Approve all. "That's `memory_promote`. They're now collective memory for every agent." |
| 3:20–4:15 | Results tab | "Same agents, same attacks, only the context changes. Isolated agents miss the slow attacks and catch the rest at the last moment. Pasting everything into every prompt catches them, at many times the tokens. Meko catches them all, earlier, with the relevant slice only. And with the approved patterns, new victims of the same attackers are stopped earlier still, without holding genuine customers." Read the three headline sentences. |
| 4:15–4:30 | Back to Live, or the README | "Collective memory, a governed learning loop, and a decision trace for every block. That's TrailGuard on Meko. Code, setup and the benchmark method are in the repo." |

**Optional extra (only if under time):** run `trailguard run --crash-at 300`, then `--resume` to show the run picking up from its Meko checkpoint. That covers "replay and resume" from Challenge 07.

**Recording tips**
- 1080p, browser zoom 110%, hide bookmarks.
- Keep the context banner visible (top right): it must say **Meko Cloud**, never "OFFLINE stand-in", in the submitted video.
- Narrate over a second take if the live run's timing doesn't match the script. The dashboard replays at the same speed for the same seed.
