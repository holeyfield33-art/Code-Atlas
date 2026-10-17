/**
 * Ruby call-extraction precision (GDK audit 2026-10-15, findings #1 and #2).
 *
 *  #1 identifiers are not calls: a local variable named `system` / `eval`, a
 *     parameter, or a method's own name must not become a call token (false
 *     OS-command / code-exec findings) or a self-edge.
 *  #2 a unique same-name definition does not prove the target: a call on a
 *     receiver of unknown type (`" x ".strip`, a local, a different constant)
 *     emits no edge; an implicit call resolves only within the caller's own
 *     class, its superclass, or a unique top-level/module method.
 * Positive controls prove real calls (recursion, vcalls, `Const.m`, `Const.new`,
 * paren-less `system cmd`, `obj.send`) still resolve and still get flagged.
 */
import assert from "node:assert/strict";
import { buildMultiLangGraph } from "../src/scanner/multilang.js";
import { scan, scanGeneric } from "../src/scanner/findings.js";
import { RUBY_RULES, PYTHON_RULES, DEFAULT_RULES } from "../src/scanner/rules.js";
import { buildGraph } from "../src/scanner/graph.js";

const files = new Map<string, string>([
  ["app/audit.rb", `def dashboards
  system = ["dashboard"]
  system
end

def permissions
  eval = { missing: [] }
  eval[:missing].empty?
end

class Unrelated
  def strip
    :unrelated
  end
end

def audit_entry
  " hello ".strip
end
`],
  ["app/abuse.rb", `module Analytics
  class DashboardService
    def response
      :analytics
    end
  end
end

class AdminController
  def organization_id
    1
  end
end

class CreateService
  def validate!
    :bulk
  end

  def execute
    validate!
  end
end

class UrlBlocker
  def self.validate!(url)
    :decoy_top_level
  end
end

module Gitlab
  module HTTP_V2
    class UrlBlocker
      def self.validate!(url)
        url
      end
    end
  end
end

class AbuseReportsController
  def create
    response = build_report
    response.success?
  end

  def build_report
    organization_id
    Gitlab::HTTP_V2::UrlBlocker.validate!("x")
  end
end
`],
  ["app/positive.rb", `def helper
  42
end

def fact(n)
  n <= 1 ? 1 : n * fact(n - 1)
end

def shell(cmd)
  system cmd
end

def literal_shell
  system "ls"
end

def kernel_shell(c)
  Kernel.system(c)
end

def code(src)
  eval(src)
end

def dispatch(obj, m)
  obj.send(m)
end

def fixed_dispatch(mailer)
  mailer.public_send(:welcome_email)
  send("reset")
end

def run_sql(conn, sql)
  conn.exec(sql)
end

def blocky(items)
  items.each { |helper| helper.to_s }
  "#{helper}"
end

class Base
  def audit_log
    :base
  end
end

class Widget < Base
  def initialize
    @x = 1
  end

  def self.build
    new
  end

  def render
    audit_log
    paint
  end

  def paint
    :ok
  end
end

def make
  Widget.build
  Widget.new
end

module Assisting
  def assist
    :help
  end
end

class Helped
  include Assisting

  def run_assist
    assist
  end
end

class NotHelped
  def go
    assist
  end
end
`],
  // Same short class name in two namespaces (GitLab has dozens of CreateService).
  ["app/namespaces.rb", `module BulkImports
  class CreateService
    def check_access!
      :bulk
    end
  end
end

module AntiAbuse
  class CreateService
    def execute
      check_access!
      Client.new
    end
  end

  class Client
    def initialize
      @c = 1
    end
  end
end

module Other
  class Client
    def initialize
      @o = 1
    end
  end
end

class Configured
  def feature_category
    :instance_side
  end
end

class UsesMacro < Configured
  feature_category
end
`],
]);

// A file cut mid-class (truncated / syntax error): its defs lose their class to
// error recovery and must not be mistaken for top-level methods.
files.set("app/broken.rb", "class Broken\n  def staged_value\n    1\n  end\n\n  def half(\n");
files.set("app/caller.rb", "class Caller\n  def go\n    staged_value\n  end\nend\n");

const b = await buildMultiLangGraph("ruby", files, "r");
const label = new Map(b.graph.nodes.map((n) => [n.id, n.label]));
const calls = b.graph.edges.filter((e) => e.kind === "calls").map((e) => `${label.get(e.from)} -> ${label.get(e.to)}`);
const has = (s: string) => calls.includes(s);
const tokensOf = (fn: string) => [...b.functionCalls].filter(([id]) => label.get(id) === fn).flatMap(([, t]) => t);
const findings = scanGeneric(b.graph, b.functionSources, b.functionCalls, RUBY_RULES).findings;
const flagged = (rule: string, fn: string) => findings.some((f) => f.id.startsWith(rule + ":") && label.get(f.nodeRefs[0]) === fn);

// ---- #1: identifiers are not calls
assert.ok(!flagged("rb-os-command", "dashboards"), "a local variable named `system` is not an OS command");
assert.ok(!flagged("rb-code-exec", "permissions"), "a local variable named `eval` is not dynamic code execution");
assert.deepEqual(tokensOf("dashboards"), [], "no call tokens from variable writes/reads");
for (const fn of ["dashboards", "permissions", "audit_entry", "helper", "shell", "paint"])
  assert.ok(!has(`${fn} -> ${fn}`), `no declaration-induced self-edge on ${fn}`);
assert.ok(!calls.some((c) => c === "Unrelated -> Unrelated" || c === "Widget -> Widget"), "class names are not calls");
assert.ok(!tokensOf("shell").includes("cmd"), "a parameter read is not a call");
assert.deepEqual(tokensOf("blocky").filter((t) => t === "helper"), ["helper"],
  "the block param `helper` is local to the block; only the later interpolated `helper` is a call");
assert.ok(has("blocky -> helper"), "after the block, `helper` in an interpolation is the real top-level call");

// ---- #2: receiver-aware resolution
assert.ok(!has("audit_entry -> strip"), "\" hello \".strip is String#strip, not Unrelated#strip");
assert.ok(!has("create -> response"), "the local `response` is not Analytics::DashboardService#response");
assert.ok(!has("build_report -> organization_id"), "an implicit call is not resolved into an unrelated class");
const blockerEdge = b.graph.edges.find((e) => e.kind === "calls" && label.get(e.from) === "build_report" && label.get(e.to) === "validate!");
assert.ok(blockerEdge, "UrlBlocker.validate! resolves by its constant receiver");
const blockerTarget = b.graph.nodes.find((n) => n.id === blockerEdge!.to)!;
assert.equal(b.functionSources.get(blockerTarget.id)?.includes("url\n"), true,
  "...to Gitlab::HTTP_V2::UrlBlocker.validate! — not CreateService#validate!, not the top-level UrlBlocker");
assert.ok(b.graph.diagnostics.some((d) => /Unresolved call 'organization_id'.*AdminController/.test(d.message)),
  "an unresolved call keeps its candidates in a diagnostic instead of guessing");

// ---- positive controls: real calls still resolve
assert.ok(has("fact -> fact"), "real recursion is kept");
assert.ok(has("create -> build_report"), "implicit call to a method of the same class");
assert.ok(has("execute -> validate!") , "implicit call resolves to the caller's own class first");
assert.ok(has("render -> paint"), "same-class implicit call");
assert.ok(has("render -> audit_log"), "implicit call resolves through the declared superclass");
assert.ok(has("make -> build"), "Const.method resolves to that class's singleton method");
assert.ok(has("make -> initialize"), "Const.new resolves to Const#initialize");
assert.ok(has("run_assist -> assist"), "implicit call resolves into a module the class includes");
assert.ok(!has("go -> assist"), "...but not into a module the caller's class never includes");

// ---- qualified owners: short-name collisions across namespaces
assert.ok(!has("execute -> check_access!"), "AntiAbuse::CreateService is not BulkImports::CreateService");
const clientNew = b.graph.edges.filter((e) => e.kind === "calls" && label.get(e.from) === "execute" && label.get(e.to) === "initialize")
  .map((e) => b.functionSources.get(e.to));
assert.deepEqual(clientNew, ["def initialize\n      @c = 1\n    end"], "`Client.new` resolves lexically to AntiAbuse::Client, not Other::Client");
assert.ok(!has("UsesMacro -> feature_category"), "a class-body call does not bind to an instance method");
assert.ok(!has("go -> staged_value"), "a def from a file that failed to parse is not treated as a top-level method");

// ---- rule precision: real sinks still fire, look-alikes do not
assert.ok(flagged("rb-os-command", "shell"), "paren-less `system cmd` is flagged");
assert.ok(!flagged("rb-os-command", "literal_shell"), "`system \"ls\"` runs one fixed command and is not reported");
assert.ok(flagged("rb-os-command", "kernel_shell"), "`Kernel.system` is flagged");
assert.ok(flagged("rb-code-exec", "code"), "`eval(src)` is flagged");
assert.ok(flagged("rb-dynamic-dispatch", "dispatch"), "`obj.send(m)` is flagged (method name from a variable, any receiver)");
assert.ok(!flagged("rb-os-command", "run_sql"), "`conn.exec(sql)` is not Kernel#exec");
assert.ok(!flagged("rb-code-exec", "fixed_dispatch"), "`send(:literal)` dispatches to one fixed method, not dynamic code");

// ---- Python: a bare sink token no longer matches an unrelated method
const py = await buildMultiLangGraph("python", new Map([["m.py",
  "import re\n\ndef pattern(p):\n    return re.compile(p)\n\ndef code(s):\n    return eval(s)\n"]]), "r");
const pyLabel = new Map(py.graph.nodes.map((n) => [n.id, n.label]));
const pyFlag = scanGeneric(py.graph, py.functionSources, py.functionCalls, PYTHON_RULES).findings
  .filter((f) => f.id.startsWith("py-code-exec:")).map((f) => pyLabel.get(f.nodeRefs[0]));
assert.deepEqual(pyFlag, ["code"], "re.compile is not builtin compile(); eval is still flagged");

// ---- JS: JSON.parse is deserialization, not input validation (audit #3)
const jsSrc = [{ path: "a.ts", code:
  "export function load(x) { return JSON.parse(x); }\n" +
  "export function check(x) { return schema.parse(x); }\n" }];
const jsGraph = buildGraph("r", jsSrc);
const js = scan(jsGraph, jsSrc, DEFAULT_RULES).findings
  .filter((f) => f.id.startsWith("c-input-validation:"))
  .map((f) => jsGraph.nodes.find((n) => n.id === f.nodeRefs[0])?.label);
assert.deepEqual(js, ["check"], "schema.parse is a validation control; JSON.parse is not");

console.log(`ruby-precision.test: ${calls.length} call edges, no variable/def-name calls, receiver-aware resolution, sinks precise`);
