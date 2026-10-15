/**
 * Generic CST → AtlasGraph mapper driven by tags.scm-style queries.
 * Emits the same node kinds (file, function, class, ...) and edge kinds
 * (contains, calls, imports) expected by the Babel backend consumers.
 *
 * Grounding invariant: never fabricate an edge. Ambiguous resolution → diagnostic.
 */

const TreeSitter = require('web-tree-sitter');
const Parser = TreeSitter.Parser || TreeSitter;
const Language = TreeSitter.Language || (TreeSitter.Parser && TreeSitter.Parser.Language);
const fs = require('fs');
const path = require('path');

/** @typedef {{ id: string, kind: string, name?: string, file?: string, range?: {start: number, end: number}, meta?: object }} AtlasNode */
/** @typedef {{ id: string, kind: string, source: string, target: string, meta?: object }} AtlasEdge */
/** @typedef {{ severity: 'error'|'warning'|'info', message: string, file?: string, range?: object }} Diagnostic */
/** @typedef {{ nodes: AtlasNode[], edges: AtlasEdge[], diagnostics: Diagnostic[] }} AtlasGraph */

const LANGUAGE_CONFIG = {
  python: {
    wasm: path.join(__dirname, 'grammars/tree-sitter-python.wasm'),
    tags: path.join(__dirname, 'queries/python/tags.scm'),
    extensions: ['.py', '.pyi'],
  },
  ruby: {
    wasm: path.join(__dirname, 'grammars/tree-sitter-ruby.wasm'),
    tags: path.join(__dirname, 'queries/ruby/tags.scm'),
    extensions: ['.rb', '.rake'],
  },
};

let parserInitialized = false;

async function initParser() {
  if (!parserInitialized) {
    await Parser.init();
    parserInitialized = true;
  }
}

/**
 * Load a language + its tags query.
 */
async function loadLanguage(lang) {
  await initParser();
  const cfg = LANGUAGE_CONFIG[lang];
  if (!cfg) throw new Error(`Unsupported language: ${lang}`);
  const language = await (Language || Parser.Language).load(cfg.wasm);
  const querySource = fs.readFileSync(cfg.tags, 'utf8');
  const Query = TreeSitter.Query;
  const query = new Query(language, querySource);
  return { language, query, cfg };
}

/**
 * Map a single file's CST tags into provisional nodes + references.
 * Returns { definitions: Map<name, nodeId[]>, references: {name, kind, range, nodeId}[], fileNodeId }
 */
function extractFromTree(tree, source, filePath, lang, query) {
  const root = tree.rootNode;
  const fileId = `file:${filePath}`;
  const definitions = new Map(); // name → [{id, kind, range}]
  const references = []; // {name, kind, range, fromId?}
  const localNodes = [];

  // File node always present
  localNodes.push({
    id: fileId,
    kind: 'file',
    name: path.basename(filePath),
    file: filePath,
    range: { start: 0, end: source.length },
    meta: { language: lang },
  });

  const captures = query.captures(root);
  // Group by match / pattern roughly by walking
  for (const { name: captureName, node } of captures) {
    if (captureName === 'name' || captureName === 'ignore' || captureName === 'doc') continue;
    // captureName is e.g. definition.function, reference.call
    const [role, kind] = captureName.split('.');
    if (!role || !kind) continue;

    // Find the associated @name capture in the same match is hard without full matches API;
    // for simplicity, look for sibling or parent name. Better: use matches().
  }

  // Prefer matches() for correct association of @name with definition/reference
  const matches = query.matches(root);
  for (const match of matches) {
    let nameNode = null;
    let defOrRef = null;
    let kind = null;
    let role = null;
    for (const cap of match.captures) {
      if (cap.name === 'name' || cap.name.endsWith('.name')) {
        nameNode = cap.node;
      } else if (cap.name.startsWith('definition.') || cap.name.startsWith('reference.')) {
        const parts = cap.name.split('.');
        role = parts[0];
        kind = parts[1];
        defOrRef = cap.node;
      }
    }
    if (!nameNode || !role || !kind) continue;
    const name = nameNode.text;
    const range = { start: nameNode.startIndex, end: nameNode.endIndex };

    if (role === 'definition') {
      const nodeId = `${kind}:${filePath}:${name}:${range.start}`;
      const node = {
        id: nodeId,
        kind: kind === 'method' ? 'function' : kind, // normalize method → function for Atlas parity
        name,
        file: filePath,
        range,
        // Full definition extent (the whole def/class/method body), distinct from
        // `range` which is just the name. Used to slice the real source of a
        // function for the native rule engine (non-JS backends can't use Babel).
        bodyRange: { start: defOrRef.startIndex, end: defOrRef.endIndex },
        meta: { language: lang, originalKind: kind },
      };
      localNodes.push(node);
      if (!definitions.has(name)) definitions.set(name, []);
      definitions.get(name).push({ id: nodeId, kind: node.kind, range, file: filePath });
      // contains edge: file → definition
      // (emitted later)
    } else if (role === 'reference') {
      references.push({
        name,
        // Fully-qualified callee token (e.g. `os.system`, `Marshal.load`), derived
        // from the real call node — distinct from the bare captured `name`. Lets
        // the native rule engine match qualified sinks precisely. Comes from a
        // parsed call, so paren-less calls are included and comments/strings are not.
        qualified: qualifiedCallee(defOrRef, name, lang),
        kind, // call, class, ...
        range,
        file: filePath,
        fromId: fileId, // provisional; could be refined to enclosing function
      });
    }
  }

  return { localNodes, definitions, references, fileId };
}

/** Reconstruct the qualified callee token from a call node (or a bare
 *  identifier/constant used as a command call). Falls back to the bare name. */
function qualifiedCallee(callNode, bareName, lang) {
  try {
    if (!callNode) return bareName;
    if (lang === 'python') {
      if (callNode.type === 'call') {
        const fn = callNode.childForFieldName('function');
        if (fn && fn.text) return fn.text;        // `os.system`, `yaml.load`, `eval`
      }
      return bareName;
    }
    if (lang === 'ruby') {
      if (callNode.type === 'call') {
        const recv = callNode.childForFieldName('receiver');
        const m = callNode.childForFieldName('method');
        const method = (m && m.text) ? m.text : bareName;
        return recv && recv.text ? recv.text + '.' + method : method; // `Marshal.load`, `system`
      }
      return bareName;                            // bare identifier/constant command call
    }
  } catch { /* fall through */ }
  return bareName;
}

/**
 * Simple import extractors (language-specific patterns, not full query for brevity).
 * Returns list of {specifier, range, isRelative}
 */
function extractImports(tree, source, lang, filePath) {
  const imports = [];
  const root = tree.rootNode;

  if (lang === 'python') {
    // Walk for import_statement / import_from_statement
    const walk = (node) => {
      if (node.type === 'import_statement') {
        for (const child of node.children) {
          if (child.type === 'dotted_name' || child.type === 'aliased_import') {
            const nameNode = child.type === 'aliased_import' ? child.childForFieldName('name') || child.children[0] : child;
            if (nameNode) {
              imports.push({
                specifier: nameNode.text,
                range: { start: nameNode.startIndex, end: nameNode.endIndex },
                isRelative: false,
              });
            }
          }
        }
      } else if (node.type === 'import_from_statement') {
        const moduleNode = node.childForFieldName('module_name');
        if (moduleNode) {
          const dots = node.children.filter(c => c.type === 'relative_import' || c.text === '.' || c.text === '..').length;
          const isRelative = dots > 0 || (moduleNode.text && moduleNode.text.startsWith('.'));
          imports.push({
            specifier: moduleNode.text || '.',
            range: { start: moduleNode.startIndex, end: moduleNode.endIndex },
            isRelative,
            level: dots,
          });
        }
      }
      for (const c of node.children) walk(c);
    };
    walk(root);
  } else if (lang === 'ruby') {
    const walk = (node) => {
      if (node.type === 'call') {
        const method = node.childForFieldName('method');
        if (method && (method.text === 'require' || method.text === 'require_relative' || method.text === 'load')) {
          const arg = node.childForFieldName('arguments') || node.children.find(c => c.type === 'argument_list');
          if (arg) {
            const str = arg.descendantsOfType('string')[0] || arg.descendantsOfType('string_content')[0];
            if (str) {
              const text = str.text.replace(/^['"]|['"]$/g, '');
              imports.push({
                specifier: text,
                range: { start: str.startIndex, end: str.endIndex },
                isRelative: method.text === 'require_relative' || text.startsWith('.'),
              });
            }
          }
        }
      }
      for (const c of node.children) walk(c);
    };
    walk(root);
  }
  return imports;
}

/**
 * Resolve import specifier to a file path within the project roots, or null + diagnostic.
 * Never invents a path.
 */
function resolveImport(specifier, fromFile, projectFiles, lang, isRelative) {
  const fromDir = path.dirname(fromFile);
  const candidates = [];

  if (lang === 'python') {
    // Simple: map dotted name to path
    let rel = specifier.replace(/\./g, '/');
    if (isRelative) {
      // crude relative
      rel = path.join(fromDir, rel);
    }
    const tryPaths = [
      rel + '.py',
      path.join(rel, '__init__.py'),
      rel,
    ];
    for (const p of tryPaths) {
      const norm = path.normalize(p).replace(/\\/g, '/');
      if (projectFiles.has(norm)) return norm;
      // also try relative to roots
      for (const root of projectFiles.roots || []) {
        const full = path.normalize(path.join(root, norm)).replace(/\\/g, '/');
        if (projectFiles.has(full)) return full;
      }
    }
  } else if (lang === 'ruby') {
    let rel = specifier.replace(/\.rb$/, '') + '.rb';
    if (isRelative || specifier.startsWith('.')) {
      rel = path.join(fromDir, rel);
    }
    const norm = path.normalize(rel).replace(/\\/g, '/');
    if (projectFiles.has(norm)) return norm;
    // Collect ALL basename/suffix matches; resolve only when exactly one exists.
    // Two files sharing a basename (lib/a/utils.rb, lib/b/utils.rb) is ambiguous,
    // not first-wins — return null so the caller records a diagnostic (grounding).
    const matches = [...projectFiles].filter((f) => f.endsWith('/' + path.basename(rel)) || f.endsWith(rel));
    return matches.length === 1 ? matches[0] : null;
  }
  return null;
}

/**
 * Build full AtlasGraph for a set of files of one language.
 */
async function buildGraph(lang, fileContents /* Map<path, source> */, projectRoot) {
  const { language, query } = await loadLanguage(lang);
  const parser = new Parser();
  parser.setLanguage(language);

  const nodes = [];
  const edges = [];
  const diagnostics = [];
  const allDefinitions = new Map(); // name → list of {id, file, kind}
  const fileIds = new Map();
  const projectFiles = new Set(fileContents.keys());
  projectFiles.roots = [projectRoot];

  // Pass 1: extract definitions + local structure
  const perFile = new Map();
  for (const [filePath, source] of fileContents) {
    const tree = parser.parse(source);
    const extracted = extractFromTree(tree, source, filePath, lang, query);
    perFile.set(filePath, { tree, source, ...extracted });

    nodes.push(...extracted.localNodes);
    fileIds.set(filePath, extracted.fileId);

    // contains edges
    for (const n of extracted.localNodes) {
      if (n.kind !== 'file') {
        edges.push({
          id: `contains:${extracted.fileId}->${n.id}`,
          kind: 'contains',
          source: extracted.fileId,
          target: n.id,
        });
      }
    }

    // collect global defs
    for (const [name, defs] of extracted.definitions) {
      if (!allDefinitions.has(name)) allDefinitions.set(name, []);
      allDefinitions.get(name).push(...defs);
    }
  }

  // Pass 2: imports
  for (const [filePath, { tree, source, fileId }] of perFile) {
    const imports = extractImports(tree, source, lang, filePath);
    for (const imp of imports) {
      const resolved = resolveImport(imp.specifier, filePath, projectFiles, lang, imp.isRelative);
      if (resolved) {
        const targetId = fileIds.get(resolved) || `file:${resolved}`;
        edges.push({
          id: `imports:${fileId}->${targetId}`,
          kind: 'imports',
          source: fileId,
          target: targetId,
          meta: { specifier: imp.specifier },
        });
      } else {
        diagnostics.push({
          severity: 'warning',
          message: `Unresolved import '${imp.specifier}' from ${filePath}`,
          file: filePath,
          range: imp.range,
        });
      }
    }
  }

  // Pass 3: call resolution (name-based, same as many tag-based systems)
  for (const [filePath, { references, fileId }] of perFile) {
    for (const ref of references) {
      if (ref.kind !== 'call') continue;
      const candidates = allDefinitions.get(ref.name) || [];
      if (candidates.length === 1) {
        edges.push({
          id: `calls:${fileId}->${candidates[0].id}`,
          kind: 'calls',
          source: fileId, // or enclosing scope if refined
          target: candidates[0].id,
          meta: { name: ref.name },
        });
      } else if (candidates.length === 0) {
        // external or builtin — diagnostic only if we want; often silent
        // diagnostics.push({ severity: 'info', message: `Unresolved call '${ref.name}'`, file: filePath, range: ref.range });
      } else {
        // ambiguous — never fabricate
        diagnostics.push({
          severity: 'warning',
          message: `Ambiguous call target for '${ref.name}' (${candidates.length} definitions); no edge emitted`,
          file: filePath,
          range: ref.range,
        });
      }
    }
  }

  // Pass 4: attribute each call's qualified token to the INNERMOST enclosing
  // definition (by bodyRange), for the native rule engine. Grounded: tokens come
  // from real parsed call nodes, so comments/strings never appear and paren-less
  // calls do. Keyed by node id.
  const callTokens = {};
  for (const [, { references, localNodes }] of perFile) {
    const defs = localNodes.filter((n) => n.bodyRange); // function/class/method defs
    for (const ref of references) {
      if (ref.kind !== 'call') continue;
      let best = null;
      for (const d of defs) {
        if (ref.range.start >= d.bodyRange.start && ref.range.end <= d.bodyRange.end) {
          if (!best || (d.bodyRange.end - d.bodyRange.start) < (best.bodyRange.end - best.bodyRange.start)) best = d;
        }
      }
      if (!best) continue; // top-level call; not inside a function
      (callTokens[best.id] ||= []).push(ref.qualified || ref.name);
    }
  }

  return { nodes, edges, diagnostics, callTokens };
}

/**
 * Produce a minimal AtlasBundle-compatible object.
 * Schema is not modified; this is a parallel emitter.
 */
function toBundle(graph, meta = {}) {
  return {
    version: 'code-atlas/1-prototype-multi',
    source: meta.source || { roots: [], generatedAt: new Date().toISOString() },
    languages: meta.languages || {},
    graph: {
      nodes: graph.nodes,
      edges: graph.edges,
      diagnostics: graph.diagnostics,
    },
  };
}

module.exports = {
  buildGraph,
  toBundle,
  LANGUAGE_CONFIG,
  loadLanguage,
};
