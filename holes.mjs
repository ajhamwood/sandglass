// Features:
// - Calculus of Construction-style dependent types
// - Type in Type
// - Normalisation by evaluation
// - Functional closures
// - De Bruijn indexing of variables
// - Metavariables


// AST
const
// Presyntax:
    RVAR   = 0,
    RLAM   = 1,
    RAPP   = 2,
    RU     = 3,
    RPI    = 4,
    RLET   = 5,
    RHOLE  = 6,
// Runtime values:
    VFLEX  = 0,
    VRIGID = 1,
    VLAM   = 2,
    VPI    = 3,
    VU     = 4,
// Term syntax:
    VAR    = 0,
    LAM    = 1,
    APP    = 2,
    U      = 3,
    PI     = 4,
    LET    = 5,
    META   = 6,
    IMETA  = 7;  // "Inserted metavariable"

function precParens (there, here, string) {
  return there > here ? `(${string})` : string
}

export function rawtermstr ([rterm_id, payload], prec = 0) {
  switch (rterm_id) {
      // case RLOC: return `RLoc ${payload[0]}`
      // case RTOP: return `RTop ${payload[0]}`
      case RVAR: return `RVar ${payload[0]}`
      case RAPP: return precParens(prec, 2, `${rawtermstr(payload[0], 2)} :@: ${rawtermstr(payload[1], 3)}`)
      case RLAM: return precParens(prec, 0, `RLam ${payload[0]}. ${rawtermstr(payload[1])}`)
      case RU:   return "RU"
      case RPI:  return precParens(prec, 1, `RPi (${payload[0]} : ${rawtermstr(payload[1], 1)}) ${rawtermstr(payload[2], 1)}`)
      case RLET: return payload[0].length == 0 ? rawtermstr(payload[3]) :
          precParens(prec, 0, `RLet ${payload[0][0]} : ${rawtermstr(payload[1][0])}\n\t= ${rawtermstr(payload[2][0])};\n` +
          `${rawtermstr(rawterm(RLET, [payload[0].slice(1), payload[1].slice(1), payload[2].slice(1), payload[3]]))}`)
      case RHOLE: return "{?}"
  }
}

function rawterm (id, payload) {
  return [id, payload]
}