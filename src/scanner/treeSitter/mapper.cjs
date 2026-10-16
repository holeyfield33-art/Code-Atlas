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
/* ---- Ruby reference classification ---------------------------------------
 * tags.scm's catch-all `[(identifier) (constant)] @reference.call` pattern leans
 * on a `#is-not? local` predicate that web-tree-sitter does NOT evaluate, so on
 * its own it reports every identifier as a call: a method's own name (self-
 * edges), its parameters, and local variables (`system = [...]` flagged as an OS
 * command). Ruby decides call-vs-variable lexically: an identifier is a local
 * variable once an assignment / parameter for it has appeared earlier in the
 * same scope. We apply exactly that rule here, plus the syntactic positions that
 * are never calls (definition names, parameters, assignment targets, constants).
 */
const sameNode = (a, b) => !!(a && b && a.type === b.type && a.startIndex === b.startIndex && a.endIndex === b.endIndex);
const fieldIs = (parent, field, node) => sameNode(parent && parent.childForFieldName(field), node);

const RB_HARD_SCOPES = new Set(['method', 'singleton_method', 'class', 'module', 'singleton_class', 'program']);
const RB_SOFT_SCOPES = new Set(['block', 'do_block', 'lambda']);       // see outer locals; own locals don't leak out
const RB_PARAM_LISTS = new Set(['method_parameters', 'lambda_parameters', 'block_parameters', 'destructured_parameter']);
const RB_NAMED_PARAMS = new Set(['optional_parameter', 'keyword_parameter', 'splat_parameter', 'hash_splat_parameter', 'block_parameter']);
const RB_MULTI_LHS = new Set(['left_assignment_list', 'destructured_left_assignment', 'rest_assignment']);

/** Is this identifier a local-variable DECLARATION (parameter or assignment target)? */
function rbIsLocalDecl(node) {
  const p = node.parent;
  if (!p) return false;
  if (RB_PARAM_LISTS.has(p.type)) return true;
  if (RB_NAMED_PARAMS.has(p.type)) return fieldIs(p, 'name', node);
  if (p.type === 'assignment' || p.type === 'operator_assignment') return fieldIs(p, 'left', node);
  if (RB_MULTI_LHS.has(p.type)) return true;
  if (p.type === 'for') return fieldIs(p, 'pattern', node);
  if (p.type === 'exception_variable') return true;                    // rescue => e
  return false;
}

/** Nearest scope node (hard or soft) enclosing `node`. */
function rbScopeOf(node) {
  for (let p = node.parent; p; p = p.parent) if (RB_HARD_SCOPES.has(p.type) || RB_SOFT_SCOPES.has(p.type)) return p;
  return null;
}

/** scopeKey:name -> earliest declaration offset, for every local in the file. */
function rbCollectLocals(root) {
  const locals = new Map();
  for (const id of root.descendantsOfType('identifier')) {
    if (!rbIsLocalDecl(id)) continue;
    const scope = rbScopeOf(id);
    const key = (scope ? scope.startIndex + ':' + scope.type : 'top') + ':' + id.text;
    const prev = locals.get(key);
    if (prev === undefined || id.startIndex < prev) locals.set(key, id.startIndex);
  }
  return locals;
}

/** Is `node` (an identifier) a read of a local declared earlier in a visible scope? */
function rbIsLocalRead(node, locals) {
  for (let p = node.parent; p; p = p.parent) {
    if (!RB_HARD_SCOPES.has(p.type) && !RB_SOFT_SCOPES.has(p.type)) continue;
    const at = locals.get(p.startIndex + ':' + p.type + ':' + node.text);
    if (at !== undefined && at < node.startIndex) return true;
    if (RB_HARD_SCOPES.has(p.type)) return false;                       // a def/class body does not see outer locals
  }
  return false;
}

/** Written constant path of a node (`Foo`, `A::B`, `::A::B`), or null if the
 *  node is not a plain constant reference (e.g. `Struct.new(...)`). */
function rbConstPath(n) {
  if (!n) return null;
  if (n.type === 'constant') return n.text;
  if (n.type === 'scope_resolution' && /^(::)?[A-Z]\w*(::[A-Z]\w*)*$/.test(n.text)) return n.text;
  return null;
}

/** Lexical nesting at `node`, innermost first, as qualified names — Ruby's
 *  Module.nesting: `module A; class B::C` → ['A::B::C', 'A']. An absolute name
 *  (`class ::X`) restarts the path. `class << self` is transparent. */
function rbNesting(node) {
  const written = [];
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === 'class' || p.type === 'module') { const nm = p.childForFieldName('name'); if (nm) written.push(nm.text); }
  }
  const out = [];
  let q = '';
  for (const w of written.reverse()) { q = w.startsWith('::') ? w.slice(2) : (q ? q + '::' + w : w); out.push(q); }
  return out.reverse();
}

/** Kind of the innermost class/module around `node`, or null at top level. */
function rbOwnerKind(node) {
  for (let p = node.parent; p; p = p.parent) if (p.type === 'class' || p.type === 'module') return p.type;
  return null;
}

/** Is this method definition a singleton (class-level) method? `def self.x`, or
 *  any `def` inside `class << self` before the enclosing class/module. */
function rbIsSingletonDef(def) {
  if (def.type === 'singleton_method') return true;
  for (let p = def.parent; p; p = p.parent) {
    if (p.type === 'singleton_class') return true;
    if (p.type === 'class' || p.type === 'module') return false;
  }
  return false;
}

/** What `self` is at a call site: an instance ('instance'), a class/module
 *  ('singleton': class bodies, `def self.x`, `class << self`), or main ('top'). */
function rbSelfContext(node) {
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === 'method') return rbIsSingletonDef(p) ? 'singleton' : 'instance';
    if (p.type === 'singleton_method' || p.type === 'singleton_class' || p.type === 'class' || p.type === 'module') return 'singleton';
  }
  return 'top';
}

/**
 * Classify a Ruby @reference.call capture. Returns null when it is not a call;
 * otherwise { receiver: 'implicit'|'self'|'constant'|'other', receiverText? }.
 */
function rbClassifyRef(nameNode, refNode, locals) {
  if (refNode && refNode.type === 'call') {                             // `recv.m(...)`, `m(...)`, `m arg`
    const recv = refNode.childForFieldName('receiver');
    if (!recv) return { receiver: 'implicit' };
    if (recv.type === 'self') return { receiver: 'self' };
    const cp = rbConstPath(recv);
    if (cp) return { receiver: 'constant', receiverText: cp };
    return { receiver: 'other' };
  }
  // the bare `[(identifier) (constant)]` pattern
  if (nameNode.type !== 'identifier') return null;                      // a constant is a reference, not a call
  const p = nameNode.parent;
  if (!p) return null;
  if (p.type === 'call' && fieldIs(p, 'method', nameNode)) return null; // already captured by the call pattern
  if ((p.type === 'method' || p.type === 'singleton_method') && fieldIs(p, 'name', nameNode)) return null; // def name
  if (p.type === 'alias' || p.type === 'undef' || p.type === 'setter') return null;
  if (rbIsLocalDecl(nameNode)) return null;
  if (rbIsLocalRead(nameNode, locals)) return null;
  return { receiver: 'implicit' };                                      // a paren-less, receiver-less call (vcall)
}

function extractFromTree(tree, source, filePath, lang, query) {
  const root = tree.rootNode;
  const fileId = `file:${filePath}`;
  const definitions = new Map(); // name → [{id, kind, range}]
  const references = []; // {name, kind, range, fromId?}
  const localNodes = [];
  const defSpans = []; // {start,end,id} full extents, for enclosing-definition lookup
  const rbLocals = lang === 'ruby' ? rbCollectLocals(root) : null;
  // ruby, all keyed by QUALIFIED class/module name (written constants are
  // resolved later, once every file's definitions are known):
  const rbKnown = [];         // qualified names of classes/modules defined here
  const rbSupers = new Map(); // class → [{ written, nesting }] superclass refs
  const rbMixins = new Map(); // class/module → [{ written, nesting, as: 'instance'|'singleton' }]
  const pushTo = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  if (lang === 'ruby') {
    for (const c of root.descendantsOfType('call')) {
      const m = c.childForFieldName('method');
      if (c.childForFieldName('receiver') || !m || !/^(include|extend|prepend)$/.test(m.text)) continue;
      const nesting = rbNesting(c);
      const args = c.childForFieldName('arguments');
      if (!nesting.length || !args) continue;
      // `include`/`prepend` add instance methods; `extend` adds singleton methods
      // (inside `class << self`, include behaves like extend).
      const inSingletonClass = !!(c.parent && c.parent.parent && c.parent.parent.type === 'singleton_class');
      const as = m.text === 'extend' || inSingletonClass ? 'singleton' : 'instance';
      for (const a of args.namedChildren) {
        const written = rbConstPath(a);
        if (written) pushTo(rbMixins, nesting[0], { written, nesting, as });
      }
    }
  }

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
      // ruby: the method's qualified lexical owner + whether it is class-level,
      // and each class/module's qualified name + superclass, for resolution
      const entry = { id: nodeId, kind: node.kind, range, file: filePath };
      if (lang === 'ruby') {
        if (defOrRef.type === 'class' || defOrRef.type === 'module') {
          const q = rbNesting(nameNode)[0];
          if (q) rbKnown.push(q);
          const sup = defOrRef.type === 'class' && defOrRef.childForFieldName('superclass');
          const written = sup && sup.namedChildren[0] ? rbConstPath(sup.namedChildren[0]) : null;
          if (q && written) pushTo(rbSupers, q, { written, nesting: rbNesting(defOrRef) }); // resolved in the outer scope
        } else if (node.kind === 'function') {
          entry.owner = rbNesting(defOrRef)[0] || null;
          entry.ownerKind = rbOwnerKind(defOrRef);
          entry.singleton = rbIsSingletonDef(defOrRef);
          // In a file that did not parse cleanly, a def outside any class may just
          // have lost its `class` to error recovery: its owner is unknown, so it
          // must not be offered as a top-level method.
          if (!entry.owner && root.hasError) entry.ownerUnknown = true;
        }
      }
      if (!definitions.has(name)) definitions.set(name, []);
      definitions.get(name).push(entry);
      // record the FULL extent of SCOPE-BEARING definitions so calls inside them
      // attribute to the enclosing scope. A constant (an assignment like
      // `X = helper()`) is NOT a scope — including it would make a top-level call
      // attribute to the constant instead of the file. Scopes only.
      if (kind === 'function' || kind === 'method' || kind === 'class' || kind === 'module')
        defSpans.push({ start: defOrRef.startIndex, end: defOrRef.endIndex, id: nodeId });
      // contains edge: file → definition
      // (emitted later)
    } else if (role === 'reference') {
      let rb = null;
      if (lang === 'ruby' && kind === 'call') {
        rb = rbClassifyRef(nameNode, defOrRef, rbLocals);
        if (!rb) continue;                       // a variable, parameter, def name or constant — not a call
        rb.nesting = rbNesting(nameNode);        // lexical scope, for constant lookup and `self`'s class
        rb.context = rbSelfContext(nameNode);    // is `self` an instance, a class/module, or main?
      }
      references.push({
        rb,
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

  return { localNodes, definitions, references, fileId, defSpans, rbKnown, rbSupers, rbMixins };
}

/** Resolve a written constant (`Foo`, `A::B`, `::A::B`) to a qualified class/
 *  module defined in the analysed files, the way Ruby looks it up: the lexical
 *  nesting innermost-out, then top level. Rails autoloading means the lexical
 *  lookup can miss, so a UNIQUE definition whose qualified name ends with the
 *  whole written path is accepted too. Anything else → null (not guessed). */
function rbResolveConst(rx, written, nesting) {
  const key = written + '\0' + (nesting[0] || '');
  if (rx.constCache.has(key)) return rx.constCache.get(key);
  let hit = null;
  if (written.startsWith('::')) hit = rx.known.has(written.slice(2)) ? written.slice(2) : null;
  else {
    for (const ns of nesting) if (rx.known.has(ns + '::' + written)) { hit = ns + '::' + written; break; }
    if (!hit && rx.known.has(written)) hit = written;
    if (!hit) {
      const tail = (rx.bySuffix.get(written.split('::').pop()) || []).filter((q) => q.endsWith('::' + written));
      if (tail.length === 1) hit = tail[0];
    }
  }
  rx.constCache.set(key, hit);
  return hit;
}

/** Where a method call on `q` is looked up, in order: the class/module itself,
 *  its mixins for that side (include/prepend → instance, extend → singleton),
 *  then its superclass, recursively. Each step names the owner to search and
 *  whether the wanted definition is a singleton (`def self.x`) or instance def. */
function rbLookupChain(rx, q, side) {
  const chain = [];
  const seen = new Set();
  for (let cur = q, depth = 0; cur && depth < 16 && !seen.has(cur); depth++) {
    seen.add(cur);
    chain.push({ owner: cur, singleton: side === 'singleton' });
    for (const mx of rx.mixins.get(cur) || []) {
      if ((mx.as === 'singleton') !== (side === 'singleton')) continue;
      const mq = rbResolveConst(rx, mx.written, mx.nesting);
      if (mq) chain.push({ owner: mq, singleton: false });   // a mixin contributes its instance defs
    }
    cur = (rx.supers.get(cur) || []).map((s) => rbResolveConst(rx, s.written, s.nesting)).find(Boolean) || null;
  }
  return chain;
}

/**
 * Ruby call resolution. A unique same-name definition somewhere in the (possibly
 * partial) project does NOT prove the target — `" x ".strip` is String#strip, not
 * some project `Unrelated#strip`. Owners are QUALIFIED (`BulkImports::CreateService`
 * is not `AntiAbuse::CreateService`), and a target is accepted only when the
 * receiver pins it:
 *  - `Const.m` / `A::B.m`  → `Const` resolved by Ruby constant lookup, then `m` on
 *                            its singleton side (or a module's instance def —
 *                            module_function / extend self); `Const.new` → `#initialize`;
 *  - implicit / `self.m`   → `self`'s class at the call site (instance or class
 *                            level), its mixins, then superclasses; else a
 *                            top-level def (private on Object);
 *  - any other receiver    → its type is unknown statically: no edge.
 * Returns { target } | { ambiguous: n } | { unresolved: reason, candidates } | null (no candidates).
 */
function resolveRubyCall(ref, rx) {
  const { receiver, receiverText, nesting, context } = ref.rb;
  const isNew = receiver === 'constant' && ref.name === 'new';
  const lookup = isNew ? 'initialize' : ref.name;
  const cands = (rx.allDefinitions.get(lookup) || []).filter((c) => c.kind === 'function');
  if (!cands.length) return null;
  const one = (xs) => (xs.length === 1 ? { target: xs[0] } : xs.length > 1 ? { ambiguous: xs.length } : null);
  const firstHit = (chain) => {
    for (const { owner, singleton } of chain) {
      const r = one(cands.filter((c) => c.owner === owner && !!c.singleton === singleton));
      if (r) return r;                               // an ambiguous step stops the walk too: never guess past it
    }
    return null;
  };
  const unresolved = (reason) => ({ unresolved: reason, candidates: cands });

  if (receiver === 'constant') {
    const q = rbResolveConst(rx, receiverText, nesting);
    if (!q) return unresolved(`constant ${receiverText} is not defined in the analysed files`);
    const hit = firstHit(rbLookupChain(rx, q, isNew ? 'instance' : 'singleton'))
      || (!isNew && one(cands.filter((c) => c.owner === q && c.ownerKind === 'module' && !c.singleton)));
    return hit || unresolved(`${q} has no ${isNew ? 'initialize' : lookup} in the analysed files`);
  }
  if (receiver === 'implicit' || receiver === 'self') {
    const self = context === 'top' ? null : nesting[0] || null;
    const hit = self && firstHit(rbLookupChain(rx, self, context === 'singleton' ? 'singleton' : 'instance'));
    if (hit) return hit;
    const top = one(cands.filter((c) => c.owner === null && !c.ownerUnknown));
    if (top) return top;
    return unresolved(`self is ${self ? self + (context === 'singleton' ? ' (class level)' : '') : 'main'}; ` +
      'no definition on its class, mixins or superclasses in the analysed files');
  }
  return unresolved('receiver type is not statically known');
}

/** The innermost definition whose full extent contains byte position `pos`,
 *  or null if the position is at module top level. */
function enclosingDefId(defSpans, pos) {
  let best = null;
  for (const d of defSpans) {
    if (d.start <= pos && pos < d.end && (!best || (d.end - d.start) < (best.end - best.start))) best = d;
  }
  return best ? best.id : null;
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
        let method = (m && m.text) ? m.text : bareName;
        // `send(:fixed_name)` / `public_send("fixed")` dispatches to ONE known method,
        // not a dynamic one: record the literal so a `send` rule token does not match.
        if (/^(send|public_send|__send__)$/.test(method)) {
          const args = callNode.childForFieldName('arguments');
          const first = args && args.namedChildren[0];
          if (first && (first.type === 'simple_symbol' || (first.type === 'string' && !first.descendantsOfType('interpolation').length)))
            method += '(' + first.text + ')';
        }
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
  const allDefinitions = new Map(); // name → list of {id, file, kind, owner, ownerKind}
  // ruby resolution context, project-wide: defined classes/modules (qualified),
  // their superclass + mixin refs (resolved lazily), and a constant-lookup cache
  const rx = { allDefinitions, known: new Set(), bySuffix: new Map(), supers: new Map(), mixins: new Map(), constCache: new Map() };
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
    for (const q of extracted.rbKnown) {
      rx.known.add(q);
      const last = q.split('::').pop();
      if (!rx.bySuffix.has(last)) rx.bySuffix.set(last, []);
      rx.bySuffix.get(last).push(q);
    }
    for (const [into, from] of [[rx.supers, extracted.rbSupers], [rx.mixins, extracted.rbMixins]]) {
      for (const [q, refs] of from) {
        if (!into.has(q)) into.set(q, []);
        into.get(q).push(...refs);
      }
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

  // Pass 3: call resolution. The edge originates at the ENCLOSING definition
  // (function/method/class) that contains the call site, falling back to the file
  // node for top-level calls. Python: unique-name. Ruby: receiver-aware (see
  // resolveRubyCall). Diagnostics are recorded once per caller + callee name.
  const ownerLabel = (c) => (c.owner ? c.owner + '#' : '') + path.basename(c.file);
  for (const [filePath, { references, fileId, defSpans }] of perFile) {
    const seen = new Set();
    const noted = new Set();
    for (const ref of references) {
      if (ref.kind !== 'call') continue;
      const srcId = enclosingDefId(defSpans, ref.range.start) || fileId;
      let res;
      if (ref.rb) res = resolveRubyCall(ref, rx);
      else {
        const candidates = allDefinitions.get(ref.name) || [];
        res = candidates.length === 1 ? { target: candidates[0] } : candidates.length > 1 ? { ambiguous: candidates.length } : null;
      }
      if (!res) continue;                           // external or builtin — silent
      if (res.target) {
        const id = `calls:${srcId}->${res.target.id}`;
        if (seen.has(id)) continue;                 // one call edge per caller→callee pair
        seen.add(id);
        edges.push({ id, kind: 'calls', source: srcId, target: res.target.id, meta: { name: ref.name } });
        continue;
      }
      const noteKey = srcId + '\0' + ref.name;
      if (noted.has(noteKey)) continue;
      noted.add(noteKey);
      const message = res.ambiguous
        // ambiguous — never fabricate
        ? `Ambiguous call target for '${ref.name}' (${res.ambiguous} definitions); no edge emitted`
        // unresolved receiver — keep the candidates visible rather than guess one
        : `Unresolved call '${ref.qualified || ref.name}': ${res.unresolved}; no edge emitted (candidates: ${
            res.candidates.slice(0, 3).map(ownerLabel).join(', ')}${res.candidates.length > 3 ? `, +${res.candidates.length - 3} more` : ''})`;
      diagnostics.push({ severity: 'warning', message, file: filePath, range: ref.range });
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
