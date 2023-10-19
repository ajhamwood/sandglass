const fs = require("node:fs/promises");

(async () => {
  const { evaluate, parse, labelledstr, rawtermstr, termstr, metastr } = await import("./holes.mjs")
  
  let evalErr, parsed, result, errmsg, errstack;
  try {
    const source = await fs.readFile("example.sa", "utf8");

    parsed = await parse(source);
    const colours = [37, 94, 32, 33, 36, 31, 93, 96, 95];
    console.log("Parsing:", "\n" + labelledstr(parsed.source, parsed.labelling, colours),"\n");
    console.log("Raw:", "\n" + rawtermstr(parsed.data, colours), "\n");

    ([evalErr, result] = await evaluate(parsed));
    if (evalErr) console.log("Error:", `\n\t${result}`);
    else console.log("Result:",
      `\n\tTerm: ${termstr(result[0])
      }\n\tType: ${termstr(result[1])
      }\n\tElab:\n${termstr(result[2])
      }\n\tMetas:\n${metastr(result[3])}`)

  } catch (e) {
    if (e.message) console.error(e.message);
    if (e.stack) throw Object.assign(new Error(""), { stack: e.stack });
  }
})().catch(console.log)