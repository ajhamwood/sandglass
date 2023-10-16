// Features:
// - Calculus of Construction-style dependent types
// - Type in Type
// - Normalisation by evaluation
// - Functional closures
// - De Bruijn indexing of variables
// - Metavariables


import { dedent } from "./utils.mjs";
import { Result, Parser } from "./parser.mjs"


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


// Source string region labels
const parser = new Parser({ labels: [
  "ws",
  "encl",
  "ident",
  "atom",
  "piBinder",
  "pi",
  "lamBinder",
  "lam",
  // "nameImpl",
  "let"
] });

function rawterm (id, payload) {
  return [id, payload]
}

// Parser combinators
class ParseHoles {

  satisfy = (pred, { errmsg } = {}) =>
    state => state.error ? Result.throw(state) : parser.peek(
      s => parser.any(s)
        .then((t, err) => !/[a-zA-Z_0-9\(\)\{\}:=;\\.\-> \r\n]/.test(t.data) ? { ...t, errmsg: "illegal" } :
          pred(t) ? t : err({ ...t, error: false, errmsg: errmsg ?? "Satisfy" })))(state)
        .then((s, err) => {
          if (s.errmsg === "illegal") {
            parser.setPos({ start: state.pos, end: s.pos });
            return err({ ...state, pos: s.pos, error: true, errmsg: `Found illegal character "${s.data}"` })
          } else return s
        }
    )
  
  cut = (p, msg, newPos) =>
    state => p(state)
      .catch(e => {
        if (!e.error) parser.setPos(newPos ?? { start: state.pos, end: e.pos });
        return parser.cut(
          Result.throw,
          e.error ? e.errmsg : msg
        )(e)
      })
  
  ws = state => parser.withLabel(
    "ws",
    parser.many(
      parser.choice([
        parser.satisfy(s => /[^\S\r\n]/g.test(s.data), { error: false, errmsg: "HWS" }),
        parser.satisfy(s => /\r\n?|\n/g.test(s.data), { error: false, errmsg: "VWS" }),
        parser.seq([
          this.symbol("--", false),
          parser.scan(s => /\r\n?|\n/g.test(s.data))
        ]),
        parser.seq([
          this.symbol("{-", false),
          parser.many(
            parser.seq([
              parser.scan(s => s.data === "-"),
              parser.satisfy(s => s.data !== "}")
            ]),
            true
          ),
          parser.scan(s => s.data === "-"),  // To improve this, use continuations?
          parser.satisfy(s => s.data === "}", { error: false, errmsg: "Multiline comment" })
        ])
      ])
    )
  )(state)
  
  parens = p => parser.withLabel(
    "encl",
    parser.do([
      this.keyword("("),
      ({}, t) => p(t),
      (s, t, u) => parser.seq([
        this.cut(
          this.keyword(")"),
          "Unclosed parens",
          { start: s.pos, end: t.pos }
        ),
        v => ({ ...v, data: u.data })
      ])(u)
    ])
  )
  
  symbol = (str, isTest = true) =>
    state => parser.map(
      parser.guard(
        parser.many(
          (isTest ? this.satisfy : parser.satisfy)(s => s.data === str[s.offset - state.offset - 1], { error: true, errmsg: `Symbol: "${str}"` })
        ),
        data => data.length === str.length
      ),
      data => data.join("")
    )(state)
  
  catchSymbol = p =>
    state => p(state)
      .catch((s, err) => !s.error ? err(s) :
        parser.mapFull(
          parser.many(
            parser.satisfy(t => /[^ \r\n]/.test(t.data))
          ),
          t => {
            parser.setPos({ start: s.pos, end: t.pos });
            return err({ ...t, data: t.data.join(""), error: true, errmsg: s.errmsg })
          }
        )(s))
  
  keyword = (str, space = false) =>
    state => parser.seq([
      this.symbol(str),
      s => (space ? this.ws : parser.option(this.ws))(s)
        .then(t => {
          parser.setPos({ start: state.pos, end: s.pos });
          return { ...t, data: s.data }
        })
    ])(state)
  
  ident = state => parser.withLabel(
    "ident",
    parser.reqr(
      this.catchSymbol(
        parser.seq([
          this.satisfy(s => /[a-zA-Z_]/.test(s.data)),
          parser.do([
            parser.many(
              this.satisfy(s => /[a-zA-Z_0-9]/.test(s.data)),
              true  // Allow zero matches
            ),
            (s, t) => {
              parser.setPos({ start: state.pos, end: t.pos });
              return { ...t, data: s.data + t.data.join("") }
            }
          ])
        ])
      ),
      parser.option(this.ws)
    )
  )(state)
  
  atom = state => parser.choice([
    parser.mapFull(
      parser.guard(
        this.ident,
        data => !~["let", "U", "_"].findIndex(x => x === data)
      ),
      s => {
        parser.setPos({ start: state.pos });
        return { ...s, data: rawterm(RVAR, [s.data]) }
      }
    ),
    parser.relabel(
      parser.map(this.keyword("U"), () => rawterm(RU, [])),
      "atom"
    ),
    parser.relabel(
      parser.map(this.keyword("_"), () => rawterm(RHOLE, [])),
      "atom"
    ),
    this.parens(this.term)
  ])(state)
  
  binder = state => parser.map(
    this.catchSymbol(
      parser.alt(
        this.ident,
        this.keyword("_")
      )
    ),
    data => [ data, parser.getPos() ]
  )(state)
  
  spine = state => parser.map(
    parser.many(
      this.atom
    ),
    data => {
      parser.setPos({ start: state.pos });
      return data.reduce((acc, a) => rawterm(RAPP, [acc, a]))
    }
  )(state)
  
  lam = state => parser.withLabel(
    "lam",
    parser.do([
      this.keyword("\\"),
      ({}, t) => {
        state.region.label = "lamBinder";
        return parser.many(
          parser.relabel(
            this.binder,
            "lamBinder"
          )
        )(t)
      },
      (s, t, u) => parser.seq([
        this.cut(
          this.keyword("."),
          "Lambda without body",
          { start: s.pos, end: t.pos }
        ),
        this.term
      ])(u),
      ({}, {}, u, v) => ({ ...v, data: u.data.reduceRight((acc, [b, pos]) => {
        parser.setPos({ start: pos[1] });
        return rawterm(RLAM, [b, acc])
      }, v.data) })
    ])
  )(state)
  
  namedPi = state => parser.withLabel(
    "pi",
    parser.seq([
      parser.many(
        this.parens(
          parser.seq([
            parser.many(
              parser.relabel(
                this.binder,
                "piBinder"
              )
            ),
            parser.do([
              parser.seq([
                this.keyword(":"),
                this.term
              ]),
              (s, t) => ({ ...t, data: s.data.map(([b, pos]) => [b, t.data, [ pos[0], t.pos ]]) })
            ])
          ])
        )
      ),
      parser.do([
        parser.seq([
          this.cut(
            this.catchSymbol(
              this.keyword("->")
            ),
            "Expected function type arrow"
          ),
          this.term
        ]),
        (s, t) => ({ ...t, data: s.data.flat(1).reduceRight((acc, [b, tm, pos]) => {
          parser.setPos({ start: pos[0] })
          return rawterm(RPI, [b, tm, acc])
        }, t.data) })
      ])
    ])
  )(state)
  
  anonPiOrSpine = state => parser.withLabel(
    "pi",
    parser.seq([
      this.cut(
        this.spine,
        "Malformed spine",
        {}
      ),
      parser.option(
        parser.do([
          parser.reql(
            this.keyword("->"),
            this.cut(
              this.catchSymbol(
                this.term
              ),
              "Malformed term",
              {}
            )
          ),
          (s, t) => {
            parser.setPos({ start: state.pos });
            return { ...t, data: rawterm(RPI, ["_", s.data, t.data]) }
          }
        ])
      )
    ])
  )(state)
  
  let_ = state => parser.withLabel(
    "let",
    parser.do([
      parser.many(
        parser.seq([
          this.keyword("let", true),
          this.cut(
            parser.map(this.binder, ([b]) => b),
            "Malformed binder",
            {}
          ),
          parser.do([
            parser.seq([
              this.cut(
                this.keyword(":"),
                'Let missing ":"'
              ),
              this.term
            ]),
            ({}, t) => parser.seq([
              this.cut(
                this.keyword("="),
                'Let missing "="'
              ),
              this.term
            ])(t),
            (s, t, u) => parser.seq([
              this.cut(
                this.keyword(";"),
                'Let missing ";"'
              ),
              v => ({ ...v, data: [s.data, t.data, u.data] })
            ])(u)
          ])
        ])
      ),
      ({}, t) => this.term(t),
      ({}, t, u) => ({
        ...u,
        data: rawterm(RLET, [
          ...t.data[0].reduce((ac1, _, i) => ac1.concat([t.data.reduce((ac2, ar) => ac2.concat([ar[i]]), [])]), []),
          u.data
        ])
      })
    ])
  )(state)
  
  term = state => parser.choice([
    this.lam,
    this.let_,
    this.namedPi,
    this.anonPiOrSpine
  ])(state)

  // Generate a parser error message
  // TODO: multiline?
  displayError = ({ source, errmsg, error }, reject) => {
    const lines = source.split(/\r\n?|\n/),
          pos = parser.getPos();
    return reject({
      message: dedent`
        ${error ? "Unmanaged p" : "P"}arser error: ${errmsg}
        ${lines[pos[0][0] - 1]}
        ${"-".repeat((pos[0][1] || 1) - 1)}${"^".repeat((pos[1][1] - pos[0][1]) || 1)} ${pos.join("-")}`
    })
  }

  constructor (state) {
    this.run = () =>
      parser.seq([
        parser.option(this.ws),
        this.cut(
          parser.do([
            this.term,
            ({}, t) => parser.option(this.ws)(t),
            ({}, {}, u) => parser.eof(u),
            ({}, t) => t
          ]),
          "No expression found"
        )
      ])(state)
        .catch(this.displayError)
        .then(state => Object.freeze({
          source: state.source,
          labelling: state.region.labelling,
          data: state.data
        }))
  }

}


// parser entry point
export async function parse (source) {
  return new ParseHoles({
    source,
    region: {
      label: "ws",
      labelling: ""
    },
    offset: 0,
    pos: [1, 0],
    data: null
  }).run()
    .toPromise()
}



// Pretty printing
export function labelledstr (source, labelling, colours) {
  let ansi = "";
  for (let i = 0; i < source.length; i++)
    ansi += (labelling[i - 1] === labelling[i] ? "" : `\x1b[${colours[parseInt(labelling[i], 36)]}m`) + source[i];
  return ansi + "\x1b[0m"
}

export function rawtermstr (rterm, colours) {
  const
    precParens = (there, here, string) => there > here ? `\x1b[${colours[1]}m(${string}\x1b[${colours[1]}m)` : string,
    rawstr = ([rterm_id, payload], prec) => {
      switch (rterm_id) {
        // case RLOC: return `RLoc ${payload[0]}`
        // case RTOP: return `RTop ${payload[0]}`
        case RVAR: return `\x1b[${colours[2]}mRVar ${payload[0]}`
        case RAPP: return precParens(prec, 2, `${rawstr(payload[0], 3)} \x1b[${colours[0]}m:@: ${rawstr(payload[1], 3)}`)
        case RLAM: return precParens(prec, 0, `\x1b[${colours[7]}mRLam \x1b[${colours[6]}m${payload[0]}\x1b[${colours[7]}m. ${rawstr(payload[1])}`)
        case RU:   return `\x1b[${colours[3]}mRU`
        case RPI:  return precParens(prec, 1, `\x1b[${colours[5]}mRPi \x1b[${colours[1]}m(\x1b[${colours[4]}m${payload[0]} \x1b[${colours[1]}m: ${rawstr(payload[1], 1)}\x1b[${colours[1]}m) ${rawstr(payload[2], 1)}`)
        case RLET: return payload[0].length == 0 ? rawstr(payload[3]) :
            precParens(prec, 0, `\x1b[${colours[8]}mRLet \x1b[${colours[2]}m${payload[0][0]} \x1b[${colours[8]}m: ${rawstr(payload[1][0])}\n\t\x1b[${colours[8]}m= ${rawstr(payload[2][0])}\x1b[${colours[8]}m;\n` +
            `${rawstr(rawterm(RLET, [payload[0].slice(1), payload[1].slice(1), payload[2].slice(1), payload[3]]))}`)
        case RHOLE: return `\x1b[${colours[3]}m{?}`
      }
    };
  return rawstr(rterm, 0) + "\x1b[0m"
}



// Evaluation: low level sketch
class EvaluateHoles {
  #metas
  #source
  infer = () => {
    return Result.pure({ term: "Hi" })
  }
  quote = () => {}
  eval = () => {}
  doElab = ({ data: rterm }) => {
    this.reset();
    return this.infer({ ctx: { env: [], names: new Map(), bds: [], lvl: 0 }, rterm })
      .catch(this.displayError)
  }
  returnAll = ({ ctx, term, vtype }) => ({
    term: this.quote({ ctx, lvl: 0, val: this.eval({ ctx, term, env: [] }) }),
    type: this.quote({ ctx, lvl: 0, val: vtype }),
    elab: term,
    metas: Array.from(this.#metas).map(([ mvar, soln ]) =>
      new metaentry([mvar, soln === null ? soln : this.quote({ ctx, lvl: 0, val: soln })]))
  })

  constructor (state) {
    let i = 0;
    this.nextMetaVar = () => i++;
    this.reset = () => {
      this.#metas = new Map();
      this.#source = state.source;
      i = 0
    };
    this.run = () => this.doElab(state)
      .then(this.returnAll)
  }
}

function metaentry([mvar, soln]) {  // Is mvar redundant here?
  return [mvar, soln]
}

export async function evaluate(state) {
  return new EvaluateHoles(state)
    .run()
    .toPromise()
}