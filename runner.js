const fs = require("node:fs/promises");

(async () => {
  const { parse } = await import("./parser.mjs"),
        { rawtermstr } = await import("./holes.mjs")
  
  let result, errmsg, errstack;
  try {
    const source = await fs.readFile("example.sa", "utf8");
    result = await parse(source);
  } catch (e) {
    errmsg = e.message
    errstack = e.stack
  }
  if (errmsg) console.error(errmsg);
  if (errstack) throw Object.assign(new Error(""), { stack: errstack });
  if (result) {
    let ansi = "";
    for (let i = 0; i < result.source.length; i++)
      switch (result.labelling[i]) {
        case "0": ansi += (result.labelling[i - 1] === "0" ? "" : "\x1b[37m") + result.source[i]; break;
        case "1": ansi += (result.labelling[i - 1] === "1" ? "" : "\x1b[94m") + result.source[i]; break;
        case "2": ansi += (result.labelling[i - 1] === "2" ? "" : "\x1b[32m") + result.source[i]; break;
        case "3": ansi += (result.labelling[i - 1] === "3" ? "" : "\x1b[33m") + result.source[i]; break;
        case "4": ansi += (result.labelling[i - 1] === "4" ? "" : "\x1b[36m") + result.source[i]; break;
        case "5": ansi += (result.labelling[i - 1] === "5" ? "" : "\x1b[31m") + result.source[i]; break;
        case "6": ansi += (result.labelling[i - 1] === "6" ? "" : "\x1b[93m") + result.source[i]; break;
        case "7": ansi += (result.labelling[i - 1] === "7" ? "" : "\x1b[96m") + result.source[i]; break;
        case "8": ansi += (result.labelling[i - 1] === "8" ? "" : "\x1b[95m") + result.source[i]; break;
      }
    ansi += "\x1b[0m";
    console.log("Parsing:", "\n" + ansi);
    console.log("AST:", "\n" + rawtermstr(result.data))
  }
})().catch(console.log)