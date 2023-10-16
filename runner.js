const fs = require("node:fs/promises");

(async () => {
  const { evaluate, parse, labelledstr, rawtermstr } = await import("./holes.mjs")
  
  let parsed, result, errmsg, errstack;
  try {
    const source = await fs.readFile("example.sa", "utf8");
    parsed = await parse(source);
    result = await evaluate(parsed)
  } catch (e) {
    errmsg = e.message
    errstack = e.stack
  }
  if (errmsg) console.error(errmsg);
  if (errstack) throw Object.assign(new Error(""), { stack: errstack });
  if (parsed) {
    const colours = [37, 94, 32, 33, 36, 31, 93, 96, 95];
    console.log("Parsing:", "\n" + labelledstr(parsed.source, parsed.labelling, colours),"\n");
    console.log("Raw:", "\n" + rawtermstr(parsed.data, colours), "\n")
    console.log("Result:", `\n\tTerm: ${result.term}\n\tType: ${result.type}\n\tElab:\n${result.elab}\n\tMetas:\n${result.metas}`)
  }
})().catch(console.log)