# Exploring a large map

The viewer remembers what you have opened, so a graph of thousands of components stays navigable.

| Control | What it does |
|---|---|
| **Explored N / total** chip | Count of components you have opened in this project. Click it for bookmarks, recently opened items, **Next unexplored**, and the dimming switch. |
| Dimming | Components you opened are drawn darker; unopened ones stay bright. Off in the **Security** view, so grade colours are always exact. |
| ☆ **Bookmark**, ✓ **Mark reviewed** | In the inspector. Bookmarks and reviewed marks are yours: they are not evidence. |
| **Next unexplored →** | Jumps to the nearest connected component you have not opened (or the best-connected unopened file). |
| **Copy shown lines / path:line / full file** | In the source section. Full file is offered only when the whole file is embedded; the panel says when a file was cut at build time. |
| **Theme** | Cycles dark, electric, light. The security grade colours are the same in all three. |

## What the states mean

- **Opened** means you clicked it. **Reviewed** means you marked it. Neither is evidence, and neither changes a
  finding, its grade or any blast radius. Tested and verified claims live in findings, not here.
- A component whose content hash has changed since you opened it counts as unexplored again, and an earlier
  "reviewed" mark no longer applies to it.

## Where it is stored

In your browser (`localStorage`), per project label, keyed by file path + kind + name. It is not written into the
bundle, is not shared, and survives restarts and rebuilds. Clearing site data, or opening the same project in a
different browser or from a different address (`file://` versus `http://127.0.0.1:4173`), starts a fresh history.

## Large graphs

The viewer draws at most 1,200 nodes; the rest stay in the bundle and in search. A component you select, bookmark or
open recently is always drawn, even if the cap would have withheld it. A node you open keeps its position while the
colours refresh, so the layout does not restart on every click.
