// Template string utility
export function dedent(callSite, ...args) {
  let size = -1;
  return callSite
    .slice(0, args.length + 1)
    .map((text, i) => (i === 0 ? "" : args[i - 1]) + text)
    .join("")
    .replace(/[\r\n]([^\S\r\n]*)/g, (_, m) => {
      if (size < 0) size = m.replace(/\t/g, "    ").length;
      return "\n" + m.slice(Math.min(m.length, size))
    })
    .replace(/^[\r\n]/, "")
}