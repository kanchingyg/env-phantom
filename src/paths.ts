import { resolve, relative, sep } from "node:path";

/** Ensure `target` resolves inside `root` (path containment). */
export function assertPathContained(target: string, root: string): string {
  const absRoot = resolve(root);
  const absTarget = resolve(absRoot, target);
  const rel = relative(absRoot, absTarget);
  if (rel.startsWith("..") || rel.includes(`${sep}..`)) {
    throw new Error(`Path outside sandbox root: ${target}`);
  }
  return absTarget;
}
