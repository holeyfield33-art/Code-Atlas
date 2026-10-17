/**
 * Calibration against a large real Rails codebase: name-only and send-only matches drowned the real leads.
 *  - rb-raw-secret needs a log / print / file / HTTP call, and skips predicates and protective names;
 *  - rb-code-exec needs string interpolation or request params (a block-form class_eval is normal Ruby);
 *  - send / public_send are reported only next to request params (rb-dynamic-dispatch);
 *  - rb-os-command needs interpolation or params (a fixed argument list is not reported);
 *  - a JS method DEFINITION named like a sink (`run(x) { ... }`) is not a call to that sink.
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";

const root = mkdtempSync(join(tmpdir(), "atlas-rbcal-"));
writeFileSync(join(root, "a.rb"), `class S
  def leak_token(user)
    Rails.logger.info("token=#{user.token}")
  end
  def token_valid?(t)
    Rails.logger.info("x")
  end
  def read_secret
    @secret
  end
  def go
    send(:perform)
  end
  def go2
    public_send(params[:m])
  end
  def reviewed(m)
    user.public_send(m) # rubocop:disable GitlabSecurity/PublicSend -- m is checked above
  end
  def blk
    self.class.class_eval do
      attr_reader :x
    end
  end
  def ev(name)
    self.class.class_eval "def #{name}; end"
  end
  def sh1
    system("git", "push")
  end
  def sh2(b)
    system("git push #{b}")
  end
end
`);
writeFileSync(join(root, "b.js"), "export function g() { return { run(x) { x.go(); } }; }\nexport function h(cmd) { return run(cmd); }\nexport function ok(cmd) { verifyCmd(cmd); return run(cmd); }\nexport function q(c) { parseInt(c); return run(c); }\n");
const { bundle } = await buildAtlas(root, {});
const N = new Map(bundle.graph.nodes.map((n) => [n.id, n.label]));
const hits = (bundle.findings ?? []).filter((f) => f.kind === "weakness").map((f) => `${f.evidence[0].source.split(":")[1]}<-${N.get(f.nodeRefs[0])}`).sort();
assert.deepEqual(hits, ["r-unguarded-sink<-h", "r-unguarded-sink<-q","rb-code-exec<-ev", "rb-dynamic-dispatch<-go2", "rb-os-command<-sh2", "rb-raw-secret<-leak_token"]);
console.log("ruby-calibration.test: Ruby rules report the interpolated / request-driven shapes only; a method definition is not a sink call");
