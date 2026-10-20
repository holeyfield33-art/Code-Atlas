# Threat overlay (optional external security leads)

Code Atlas owns the code graph. A **threat overlay** lets an outside source, such as the
ASI Threat Graph service, annotate that graph with security *leads* (hypotheses to
investigate). It is optional: without it Code Atlas behaves exactly as before.

```
code-atlas build /path/to/your/repo --asi-overlay overlay.json
code-atlas build /path/to/your/repo --asi-overlay https://your-asi-host/overlay.json
```

The viewer shows the result in the **Threat Map** mode (04). Agents get it through
`atlas_threats` (a `leads` array) and `atlas_overview` (`threatOverlay` summary).

## What the overlay can and cannot do

- It **annotates**: it never adds nodes or edges, and never changes a finding.
- It **cannot make a weakness**. A node is only a verified weakness (red) when a finding
  graded OBSERVED/TESTED on *this* repo says so. A lead is shown in its own colour and
  labelled a hypothesis.
- A lead whose `target` does not match **exactly one** node is kept as *unresolved*, with
  the reason. It is never attached to a best guess. Unresolved means unknown, not cleared.
- Status is shown as the source reported it, with one rule: `observed` or `verified`
  with no `evidence` is shown as `inferred`. Nothing is ever upgraded.
- A source that is missing, unreachable, malformed or too large does not fail the build.
  The map is built without it and the reason is printed and stored in the bundle
  `diagnostics`.

## Contract (schemaVersion "1")

```json
{
  "schemaVersion": "1",
  "source": { "identity": "asi-threat-graph", "ref": "<pinned revision>", "asOf": "<date>" },
  "leads": [
    {
      "id": "lead-1",
      "attackClassId": "AAC-01",
      "label": "Direct Prompt Injection",
      "target": "src/handler.js#handlePrompt",
      "status": "hypothetical",
      "confidence": "low",
      "note": "Why the source thinks this place is worth a look.",
      "rule": "optional name of the mapping rule",
      "url": "https://optional.example/page-for-this-class",
      "evidence": [{ "source": "optional", "detail": "optional" }]
    }
  ],
  "unresolved": [
    { "id": "u-1", "attackClassId": "AAC-29", "description": "No mapping found for this class", "target": "optional" }
  ]
}
```

- `target`: a node id, `path#functionName`, or a file path. A leading `ATLAS:fn:` /
  `ATLAS:file:` is accepted and ignored.
- `status`: `hypothetical`, `inferred`, `observed`, `verified`, `refuted`.
- `confidence`: `low` (default), `medium`, `high`.
- `url` must be `http(s)`. Other schemes are rejected.
- Limits: 5 MB document, 5,000 leads, 5,000 unresolved entries, 10 s fetch timeout, no
  redirects when fetched over HTTP.

## Limits

- Code Atlas does not decide *which* attack class applies to which code. That mapping is
  the source's job, and a lead is only as good as its rule.
- Targets are matched by name and path. A function that moved or was renamed since the
  source produced its leads becomes unresolved, not re-guessed.
- On a sharded repo, build the overlay per shard; a lead whose target is in another
  shard is unresolved there.
