# Ingesting folders and projects

## The flow

1. From the Code Atlas checkout, run `npm ci`, `npm run build`, then `npm start`.
2. Open `http://127.0.0.1:4173` and click **Open folder**.
3. Select the entire project folder and confirm the browser prompt. Supported source files are filtered, analyzed, and displayed automatically.
4. Use **Save bundle** to download the snapshot and **Load bundle** to reopen it.
5. Select the folder again after source changes. There is no automatic refresh.

The folder picker sends eligible source files to the Code Atlas process on your own computer. It does not send them to an external service or execute project code. Files are analyzed in a temporary directory that is removed after processing. The resulting bundle stays in the page until you save it. Reloading the app starts with a sample graph, so save a bundle before leaving if you need the snapshot. There is no project registry, watch mode, or incremental index.

Folder selection requires a browser supporting directory inputs, such as Chrome or Edge. The browser may call this an upload even though the destination is your local app. Unsupported files, excluded directories, and files over 200,000 bytes are filtered before transmission; a skipped-file count appears after loading. The app rejects more than 2,000 eligible files or over 24 MiB of selected source rather than silently truncating the selection. The HTTP request limit is 32 MiB including JSON encoding. Select a smaller source folder if a limit is exceeded.

Offline generated HTML files cannot run the Node-based analyzers by themselves. Use the local app URL for **Open folder**, or generate bundles with the CLI below. CLI builds replace the two files in their output directory. Source files in the input project are read, not modified. Keep output separate from source.

## CLI: one project

From the Code Atlas checkout, after `npm ci` and `npm run build`:

```powershell
npm start -- build "C:\path\to\my-project" --out "atlas/my-project"
Start-Process .\atlas\my-project\viewer.html
```

Quote paths containing spaces. The input can be any local folder, including a subfolder of a repository. Paths and graph relationships are relative to the selected root: scanning only `src` excludes tests or other sibling folders and prevents resolving their relationships.

## Multiple projects

Keep independent snapshots in separate output folders:

```powershell
npm start -- build "C:\projects\frontend" --out "atlas/frontend"
npm start -- build "C:\projects\backend" --out "atlas/backend"
```

Open either viewer, then use **Load bundle** to switch between their JSON files. Loading replaces the current graph. One build accepts one root; there is no CLI command to merge existing bundles.

For a monorepo, scan the common root to include its supported projects in one map. You can also scan a common parent folder for several repositories, but only statically resolvable relationships appear, and the same scan limits apply across the entire root. Prefer separate snapshots for unrelated repositories.

## Scan boundaries

The scanner recursively reads supported source files without executing them or following symbolic links. It uses a fixed exclusion list, not `.gitignore` or user-configurable ignore patterns:

```text
node_modules .git dist build .next coverage .course atlas .turbo out
vendor __pycache__ .venv venv
```

These names are skipped at every directory level. The default limits are 2,000 source files and 200,000 bytes per file. For CLI builds `--max-files <n>` and `--max-bytes <n>` change these limits; the folder picker in the app is fixed at the defaults. Every omitted file is counted by reason (unsupported, too large, over the cap, symlink, ignored directory, unreadable) in the bundle's `coverage` field, and `build` prints the summary, so a map never silently hides that it is partial. The files are counted, not listed by name. Supported extensions are case-sensitive: JS/TS variants, `.vue`, `.py`, `.pyi`, `.rb`, and `.rake`.

The graph analyzes eligible files before source excerpts are capped at 40,000 characters per file for embedding. Consequently, source shown in the viewer or MCP may be incomplete for large files even when graph nodes exist. A Vue file without a script block contributes no Babel graph nodes. Unsupported languages and non-source assets are not mapped.

## Refresh and triage

The HTML embeds a snapshot of the JSON at generation time. Editing the JSON later does not update the HTML. After an MCP triage decision, load the updated JSON through **Load bundle** to see it. Rebuilding regenerates findings and does not preserve prior triage decisions; save a copy of a triaged bundle if you need that record. An MCP server loads its bundle at startup, so restart it after an external rebuild.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Folder button asks you to start the app | Run `npm start` and open its local URL instead of the offline HTML |
| Port 4173 is busy | Run `npm start -- serve --port 4174` and use the printed URL |
| Folder analysis fails | Read the displayed error; select a smaller source folder if a limit is exceeded |
| No supported source files | Check the folder, extensions, fixed exclusions, size limit, and symlinks |
| Results appear under the wrong folder | `--out` is relative to the terminal working directory; use an absolute output path if needed |
| Old graph after editing source | Rebuild and reopen the HTML or load the new bundle JSON |
| No lessons or missing relationships | Inspect diagnostics; lessons require eligible functions and static analysis cannot resolve all calls/imports |
| Viewer shows a sample graph | Open the generated output HTML rather than `viewer/viewer.html`, the source template |
| Blank 3D canvas | Use a browser with WebGL enabled; check its developer console for errors |

Generated HTML and JSON include source. Review both before sharing; pattern-based secret redaction cannot guarantee removal of sensitive data.
