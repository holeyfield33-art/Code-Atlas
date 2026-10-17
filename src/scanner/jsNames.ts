/**
 * Shared naming for JS/TS function-like members, so the graph builder (which creates
 * the node) and the findings scanner (which slices that node's source by name) always
 * agree on the key. Class members are labelled `Class.member`.
 *
 * Why this exists: before class methods were mapped, a TypeScript codebase written
 * with classes (a store, a vault, a service) was almost invisible to the scanner: its
 * file writes and database calls lived in methods that had no node, so no rule ever saw
 * them. Plain `function` declarations and `const f = () => {}` were the only functions.
 */

/** Name of the class that owns the member at `p` (a ClassMethod / ClassPrivateMethod /
 *  ClassProperty path), or null if it cannot be named (anonymous class). */
function owningClassName(p: any): string | null {
  const cls = p.parentPath?.parentPath;                 // member -> ClassBody -> Class(Declaration|Expression)
  if (!cls || (cls.node?.type !== "ClassDeclaration" && cls.node?.type !== "ClassExpression")) return null;
  if (cls.node.id?.name) return cls.node.id.name;
  const decl = cls.parentPath?.node;                    // `const Foo = class { ... }`
  if (decl?.type === "VariableDeclarator" && decl.id?.type === "Identifier") return decl.id.name;
  return null;
}

/** `Class.member` for a class member that has a function body, else null. Computed keys,
 *  overload signatures (no body) and anonymous classes are skipped: they cannot be named
 *  honestly. */
export function classMemberLabel(p: any): string | null {
  const n = p.node;
  let member: string | null = null;
  if (n.type === "ClassMethod") {
    if (!n.body || n.computed) return null;
    member = n.key?.type === "Identifier" ? n.key.name : n.key?.type === "StringLiteral" ? n.key.value : null;
  } else if (n.type === "ClassPrivateMethod") {
    if (!n.body) return null;
    member = n.key?.id?.name ? "#" + n.key.id.name : null;
  } else if (n.type === "ClassProperty") {                // `handler = async () => { ... }`
    const v = n.value?.type;
    if (n.computed || (v !== "ArrowFunctionExpression" && v !== "FunctionExpression")) return null;
    member = n.key?.type === "Identifier" ? n.key.name : null;
  } else return null;
  if (!member) return null;
  const cls = owningClassName(p);
  return cls ? `${cls}.${member}` : null;
}
