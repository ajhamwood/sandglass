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
    RVAR   = 0, // str name
    RLAM   = 1, // str name, rterm body
    RAPP   = 2, // rterm func, rterm arg
    RU     = 3, // empty
    RPI    = 4, // str name, rterm domain, rterm codomain
    RLET   = 5, // str[] names, rterm[] types, rterm[] terms, rterm result
    RHOLE  = 6, // empty
// Runtime values:
    VFLEX  = 0, // int mvar, value[] spine
    VRIGID = 1, // int lvl, value[] spine
    VLAM   = 2, // str name, term body, value[] closure
    VPI    = 3, // str name, value domain, term codomain, value[] closure
    VU     = 4, // empty
// Term syntax:
    VAR    = 0, // int level
    LAM    = 1, // str name, term body
    APP    = 2, // term func, term arg
    U      = 3, // empty
    PI     = 4, // str name, term domain, term codomain
    LET    = 5, // str[] names, term[] types, term[] terms, term result
    META   = 6, // int mvar
    IMETA  = 7; // int mvar, bool[] binder_or_definitions


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


export function termstr ([term_id, payload], names = [], prec = 0) {
  const
    fresh = (names, name) => name === "_" ? "_" : names.reduce((acc, n) => new RegExp(`^${acc}[']*$`).test(n) ? n + "'" : acc, name),
    precParens = (there, here, string) => there > here ? `(${string})` : string,
    lamstr = (names, name, [body_tid, body_payload]) => {
      let res;
      const ns = names.concat([name]);
      if (body_tid !== LAM) res = `. ${termstr([body_tid, body_payload], ns, 0)}`;
      else {
        const n = fresh(ns, body_payload[0]);
        res = ` ${n}${lamstr(ns, n, body_payload[1])}`;
      }
      return res
    },
    pibind = (names, name, dom) => `(${name} : ${termstr(dom, names, 0)})`,
    pistr = (names, name, [cod_tid, cod_payload]) => {
      let res;
      const ns = names.concat([name]);
      if (cod_tid !== PI) res = ` -> ${termstr([cod_tid, cod_payload], ns, 1)}`;
      else if (cod_payload[0] === "_") res = ` -> ${termstr(cod_payload[1], ns, 2)} -> ${termstr(cod_payload[2], ns.concat(["_"]), 1)}`;
      else {
        const n = fresh(ns, cod_payload[0]);
        res = pibind(ns, n, cod_payload[1]) + pistr(ns, n, cod_payload[2])
      }
      return res
    };
  let str, name;
  switch (term_id) {
    case VAR:
      let lvl = names.length - payload[0] - 1;
      return lvl >= names.length ? `@` + payload[0] :
        lvl >= 0 ? names[lvl] : `#${-1 - lvl}`
    case APP: return precParens(prec, 2, `${termstr(payload[0], names, 2)} ${termstr(payload[1], names, 3)}`)
    case LAM:
      name = fresh(names, payload[0]);
      return precParens(prec, 0, `\\${name}${lamstr(names, name, payload[1])}`)
    case PI:
      name = fresh(names, payload[0]);
      str = name === "_" ? `${termstr(payload[1], names, 2)} -> ${termstr(payload[2], names.concat(["_"]), 1)}` :
        pibind(names, name, payload[1]) + pistr(names, name, payload[2]);
      return precParens(prec, 1, str)
    case U:
      return "U"
    case LET:
      let ns = names.slice();
      str = "";
      for (let i = 0; i < payload[0].length; i++) {
        name = fresh(ns, payload[0]);
        str += `let ${payload[0][i]} : ${termstr(payload[1][i], ns)}\n\t= ${termstr(payload[2][i], ns)};\n`;
        ns = ns.concat([payload[0][i]]);
      }
      return precParens(prec, 0, str + termstr(payload[3], ns))
    case META:
      return `?${payload[0]}`
    case IMETA:
      str = `?${payload[0]}${names.filter(({}, i) => payload[1][i]).map(n => ` ${n}`).join("")}`;
      return precParens(prec, 2, str)
  }
}

export function metastr (mvar, soln) {
  return `let ?${mvar} = ${soln === null ? "?" : termstr(soln)};\n`
}



// Evaluation: low level sketch
class EvaluateHoles {
  #metas    // [int mvar, term soln][]
  #source   // str source
  #nextMeta // int nextMeta

  eval = ([term_id, payload], env, ctx) => {
    let result;
    switch (term_id) {
      case VAR:
        result = env[env.length - payload[0] - 1];
        break;
      case LAM:
        result = value(VLAM, [payload[0], payload[1], env]);
        break;
      case APP:
        const func = this.eval(payload[0], env, ctx),
              arg = this.eval(payload[1], env, ctx);
        result = this.vApp(func, arg, ctx);
        break;
      case U:
        result = value(VU, []);
        break;
      case PI:
        const dom = this.eval(payload[1], env, ctx);
        result = value(VPI, [payload[0], dom, payload[2], env]);
        break;
      case LET:
        let newVal, newEnv = env.slice();
        for (let i = 0; i < payload[2].length; i++) {
          newVal = this.eval(payload[2][i], newEnv, ctx);
          newEnv.push(newVal);
        }
        result = this.eval(payload[3], newEnv, ctx);
        break;
      case META:
        result = this.vMeta(payload[0]);
        break;
      case IMETA:
        const meta = this.vMeta(payload[0]);
        result = this.vAppBDs(meta, env, payload[1], ctx)
    }
    return result
  }
  cApp = (val, term, env, ctx) => {
    const newEnv = env.concat([val]);
    return this.eval(term, newEnv, ctx)
  }
  vApp = ([vfunc_id, payload], varg, ctx) => {
    let result, newSpine;
    switch (vfunc_id) {
      case VLAM:
        result = this.cApp(varg, payload[1], payload[2], ctx);
        break;
      case VFLEX:
        newSpine = payload[1].concat([ varg ]);
        result = value(VFLEX, [payload[0], newSpine]);
        break;
      case VRIGID:
        newSpine = payload[1].concat([ varg ]);
        result = value(VRIGID, [payload[0], newSpine])
    }
    return result
  }
  vAppSp = (val, spine, ctx) => {
    let result = val;
    for (let i = 0; i < spine.length; i++)
      result = this.vApp(result, spine[i], ctx);
    return result
  }
  vMeta = mvar => {
    const [, soln] = this.#metas.find(([m]) => m === mvar);
    return soln === null ? value(VFLEX, [mvar, []]) : soln
  }
  vAppBDs = (val, env, bds, ctx) => {
    let result = val;
    for (let i = 0; i < bds.length; i++)
      result = bds[i] ? this.vApp(result, env[i], ctx) : result;
    return result
  }

  quote = ([val_id, payload], lvl, ctx) => {
    let result, newTerm, newVal, freshVal;
    switch (val_id) {
      case VFLEX:
        newTerm = term(META, [payload[0]]);
        result = this.quoteSp(newTerm, payload[1], lvl, ctx);
        break;
      case VRIGID:
        newTerm = term(VAR, [lvl - payload[0] - 1]);
        result = this.quoteSp(newTerm, payload[1], lvl, ctx);
        break;
      case VLAM:
        freshVal = value(VRIGID, [lvl, []]);
        newVal = this.cApp(freshVal, payload[1], payload[2], ctx);
        newTerm = this.quote(newVal, lvl + 1, ctx);
        result = term(LAM, [payload[0], newTerm]);
        break;
      case VPI:
        freshVal = value(VRIGID, [lvl, []]);
        newVal = this.cApp(freshVal, payload[2], payload[3]);
        newTerm = this.quote(newVal, lvl + 1, ctx);
        const newDom = this.quote(payload[1], lvl, ctx);
        result = term(PI, [payload[0], newDom, newTerm])
        break;
      case VU:
        result = term(U, [])
    }
    return result
  }
  quoteSp = (tm, spine, lvl, ctx) => {
    let result = tm;
    for (let i = 0; i < spine.length; i++) {
      let arg = this.quote(spine[i], lvl, ctx);
      result = term(APP, [result, arg]);
    }
    return result
  }
  force = ([val_id, payload], ctx) => {
    if (val_id !== VFLEX) return [val_id, payload];
    const [, soln] = this.#metas.find(([m]) => m == payload[0]);
    if (soln === null) return [val_id, payload];
    const newVal = this.vAppSp(soln, payload[1], ctx);
    return this.force(newVal, ctx)
  }

  getNextMeta = () => this.#nextMeta++;
  reset = () => {
    this.#metas = [];
    this.#nextMeta = 0
  }
  freshMeta = ([lvl, env, names, types, bds]) => {
    const mvar = this.getNextMeta();
    this.#metas.push([mvar, null]);
    return term(IMETA, [mvar, bds])
  }

  bind = (vtype, name, [lvl, env, names, vtypes, bds]) => {
    const freshVal = value(VRIGID, [lvl, []]),
          newEnv = structuredClone(env).concat([freshVal]),
          newNames = names.concat([name]),
          newTypes = structuredClone(vtypes).concat([vtype]),
          newBDs = bds.concat([true]);
    return [lvl + 1, newEnv, newNames, newTypes, newBDs]
  }
  define = (val, vtype, name, [lvl, env, names, vtypes, bds]) => {
    const newEnv = structuredClone(env).concat([val]),
          newNames = names.concat([name]),
          newTypes = structuredClone(vtypes).concat([vtype]),
          newBDs = bds.concat([false]);
    return [lvl + 1, newEnv, newNames, newTypes, newBDs]
  }

  liftPRen = ([occ, dom, cod, ren]) => {
    const newRen = structuredClone(ren),
          i = newRen.findIndex(([c]) => c === cod);
    if (~i) newRen[i][1] = dom;
    else newRen.push([cod, dom]);
    return [occ, dom + 1, cod + 1, newRen]
  }
  invertPRen = (spine, lvl, ctx) => {
    let dom = 0, ren = [];
    for (let i = 0; i < spine.length; i++) {
      const [fval_id, payload] = this.force(spine[i], ctx);
      if (fval_id === VRIGID && payload[1].length === 0) {
        const i = ren.findIndex(([c]) => c === payload[0]);
        if (!~i) {
          ren.push([payload[0], dom]);
          dom++;
          continue
        }
      } // TODO: use error codes
      return [1, "Unification error: Must substitute on unblocked variable"];
    }
    return [0, [null, dom, lvl, ren]]
  }
  rename = (val, pren, ctx) => {
    const [fval_id, payload] = this.force(val, ctx),
          [occ, dom, cod, ren] = pren;
    let err = 0, result, i, newTerm, newVal, newPren, freshVal, newDom;
    switch (fval_id) {
      case VFLEX:
        if (occ === payload[0]) return [1, "Unification error: occurs check"];
        result = term(META, [payload[0]]);
        for (let i = 0; i < payload[1].length; i++) {
          ([err, newTerm] = this.rename(payload[1][i], pren, ctx));
          if (err) {
            result = newTerm;
            break
          }
          result = term(APP, [result, newTerm])
        }
        break;
      case VRIGID:
        i = ren.findIndex(([c]) => c === payload[0]);
        if (!~i) return [1, "Unification error: variable escapes scope"];
        result = term(VAR, [dom - ren[i][1] - 1]);
        for (let i = 0; i < payload[1].length; i++) {
          ([err, newTerm]  = this.rename(payload[1][i], pren, ctx));
          if (err) {
            result = newTerm;
            break
          }
          result = term(APP, [result, newTerm])
        }
        break;
      case VLAM:
        newPren = this.liftPRen(pren);
        freshVal = value(VRIGID, [cod, []]);
        newVal = this.cApp(freshVal, payload[1], payload[2], ctx);
        ([err, result] = this.rename(newVal, newPren, ctx));
        if (err) break;
        result = term(LAM, [payload[0], result]);
        break;
      case VPI:
        ([err, result] = this.rename(payload[1], pren, ctx));
        if (err) break;
        newDom = result;
        newPren = this.liftPRen(pren);
        freshVal = value(VRIGID, [cod, []]);
        newVal = this.cApp(freshVal, payload[2], payload[3], ctx);
        ([err, result] = this.rename(newVal, newPren, ctx));
        if (err) break;
        result = term(PI, [payload[0], newDom, result]);
        break;
      case VU:
        result = term(U, [])
    }
    return [err, result]
  }

  solve = (val, spine, lvl, mvar, ctx) => {
    let err, newPren, result, i;
    ([err, newPren] = this.invertPRen(spine, lvl, ctx));
    if (err) return [1, newPren];
    newPren[0] = mvar;  // occurs check
    ([err, result] = this.rename(val, newPren, ctx));
    if (err) return [1, result];
    for (let i = newPren[1]; i > 0; i--)
      result = term(LAM, ["x" + i, result]);
    result = this.eval(result, [], ctx);
    i = this.#metas.findIndex(([m]) => m === mvar);
    if (~i) this.#metas[i][1] = result;
    else this.#metas.push([mvar, result]);
    return [0]
  }
  unify = (val0, val1, lvl, ctx) => {
    const [fval0_id, payload0] = this.force(val0, ctx),
          [fval1_id, payload1] = this.force(val1, ctx);
    let err, result;
    if (fval0_id === VU && fval1_id === VU) err = 0;
    else if (fval0_id === VPI && fval1_id === VPI) {
      ([err, result] = this.unify(payload0[1], payload1[1], lvl, ctx));
      if (!err) {
        const freshVal0 = value(VRIGID, [lvl, []]),
              val0 = this.cApp(freshVal0, payload0[2], payload0[3], ctx),
              freshVal1 = value(VRIGID, [lvl, []]),
              val1 = this.cApp(freshVal1, payload1[2], payload1[3], ctx);
        ([err, result] = this.unify(val0, val1, lvl + 1, ctx))
      }
    }
    else if (fval0_id === VRIGID && fval1_id === VRIGID && payload0[0] === payload1[0])
      ([err, result] = this.unifySp(payload0[1], payload1[1], lvl, ctx));
    else if (fval0_id === VFLEX && fval1_id === VFLEX && payload0[0] === payload1[0])
      ([err, result] = this.unifySp(payload0[1], payload1[1], lvl, ctx));
    else if (fval0_id === VLAM && fval1_id === VLAM) {
      const freshVal0 = value(VRIGID, [lvl, []]),
            val0 = this.cApp(freshVal0, payload0[1], payload0[2], ctx),
            freshVal1 = value(VRIGID, [lvl, []]),
            val1 = this.cApp(freshVal1, payload1[1], payload1[2], ctx);
      ([err, result] = this.unify(val0, val1, lvl + 1, ctx))
    } else if (fval0_id === VLAM) {
      const freshVal0 = value(VRIGID, [lvl, []]),
            val0 = this.cApp(freshVal0, payload0[1], payload0[2], ctx),
            freshVal1 = value(VRIGID, [lvl, []]),
            val1 = this.vApp([fval1_id, payload1], freshVal1, ctx);
      ([err, result] = this.unify(val0, val1, lvl + 1, ctx))
    }
    else if (fval1_id === VLAM) {
      const freshVal0 = value(VRIGID, [lvl, []]),
            val0 = this.vApp([fval0_id, payload0], freshVal0, ctx),
            freshVal1 = value(VRIGID, [lvl, []]),
            val1 = this.cApp(freshVal1, payload1[1], payload1[2], ctx);
      ([err, result] = this.unify(val0, val1, lvl + 1, ctx))
    }
    else if (fval0_id === VFLEX)
      ([err, result] = this.solve([fval1_id, payload1], payload0[1], lvl, payload0[0], ctx))
    else if (fval1_id === VFLEX)
      ([err, result] = this.solve([fval0_id, payload0], payload1[1], lvl, payload1[0], ctx))
    else ([err, result] = [1, "Unification error: rigid mismatch"]);
    return [err, result]
  }
  unifySp = (sp0, sp1, lvl, ctx) => {
    if (sp0.length !== sp1.length) return [1, "Unification error: rigid mismatch"];
    for (let i = 0; i < sp0.length; i++) {
      const [err, msg] = this.unify(sp0[i], sp1[i], lvl, ctx);
      if (err) return [1, msg]
    }
    return [0]
  }
  unifyCatch = (val0, val1, ctx) => {
    const [lvl, env, names, vtypes, bds] = ctx,
          [err, msg] = this.unify(val0, val1, lvl, ctx);
    if (err) {
      const term0 = this.quote(val0, lvl, ctx),
            term1 = this.quote(val1, lvl, ctx);
      return [1, `${msg}\nCan't unify\n\t${termstr(term0, names)}\nwith\n\t${termstr(term1, names)}`]
    } else return [0]
  }

  check = (rterm, vtype, ctx) => {
    const [rterm_id, payloadr] = rterm,
          [lvl, env, names, vtypes, bds] = ctx,
          [fvtype_id, payloadfv] = this.force(vtype, ctx);
    let err, result;
    if (rterm_id === RLAM && fvtype_id === VPI) {
      const newCtx = this.bind(payloadfv[1], payloadr[0], ctx),
            freshVal = value(VRIGID, [lvl, []]),
            newVal = this.cApp(freshVal, payloadfv[2], payloadfv[3], newCtx);
      ([err, result] = this.check(payloadr[1], newVal, newCtx));
      if (!err) result = term(LAM, [payloadr[0], result])
    }
    else if (rterm_id === RLET) {
      const lnames = [], types = [], terms = [], newCtx = ctx;
      for (let i = 0; i < payloadr[0].length; i++) {
        lnames.push(payloadr[0][i]);
        const uVal = value(VU, []);
        ([err, result] = this.check(payloadr[1][i], uVal, newCtx));
        if (err) break;
        types.push(result);
        const cvtype = this.eval(result, env, newCtx);
        ([err, result] = this.check(payloadr[2][i], cvtype, newCtx));
        if (err) break;
        terms.push(result);
        const newVal = this.eval(result, env, newCtx);
        newCtx = this.define(newVal, cvtype, payloadr[0][i], newCtx);
      }
      if (!err) {
        ([err, result] = this.check(payloadr[3], [fvtype_id, payloadfv], newCtx));
        if (!err) result = term(LET, [lnames, types, terms, result])
      }
    }
    else if (rterm_id === RHOLE) ([err, result] = [0, this.freshMeta(ctx)]);
    else {
      ([err, result] = this.infer(rterm, ctx));
      if (!err) {
        const [ivtype, tm] = result;
        ([err, result] = this.unifyCatch([fvtype_id, payloadfv], ivtype, ctx));
        if (!err) result = tm
      }
    };
    return [err, result]
  }
  infer = ([rterm_id, payloadr], ctx) => {
    let err = 0, result, vtype, dom, newCtx, newVal, tm;
    const [lvl, env, names, vtypes, bds] = ctx,
          uVal = value(VU, []);
    switch (rterm_id) {
      case RVAR:
        const i = names.findLastIndex(n => n === payloadr[0]);
        err = ~i ? 0 : 1;
        if (~i) {
          tm = term(VAR, [lvl - i - 1]);
          result = [vtypes[i], tm]
        } else result = `Evaluator error: name not in scope "${payloadr[0]}"`
        break;
      case RLAM:
        const newMeta = this.freshMeta(ctx);
        vtype = this.eval(newMeta, env, ctx);
        newCtx = this.bind(vtype, payloadr[0], ctx);
        ([err, result] = this.infer(payloadr[1], newCtx));
        if (err) break;
        const [ivtype, body] = result,
              clsTerm = this.quote(ivtype, lvl + 1, ctx);
        tm = term(LAM, [payloadr[0], body]);
        vtype = value(VPI, [payloadr[0], vtype, clsTerm, env]);
        result = [vtype, tm];
        break;
      case RAPP:
        ([err, result] = this.infer(payloadr[0], ctx));
        if (err) break;
        [vtype, tm] = result;
        const [fvtype_id, payloadfv] = this.force(vtype, ctx);
        let clsTm, clsEnv;
        if (fvtype_id === VPI) {
          dom = payloadfv[1]
          clsTm = payloadfv[2]
          clsEnv = payloadfv[3];
        } else {
          const newMeta = this.freshMeta(ctx);
          dom = this.eval(newMeta, env, ctx);
          newCtx = this.bind(dom, "x", ctx);
          clsTm = this.freshMeta(newCtx);
          clsEnv = env;
          const newVal = value(VPI, ["x", dom, clsTm, env]);
          ([err, result] = this.unifyCatch(newVal, vtype, ctx));
          if (err) break
        }
        ([err, result] = this.check(payloadr[1], dom, ctx));
        if (err) break;
        newVal = this.eval(result, env, ctx);
        vtype = this.cApp(newVal, clsTm, clsEnv, ctx);
        tm = term(APP, [tm, result]);
        result = [vtype, tm];
        break;
      case RU:
        tm = term(U, []);
        result = [uVal, tm];
        break;
      case RPI:
        ([err, result] = this.check(payloadr[1], uVal, ctx));
        if (err) break;
        dom = result;
        vtype = this.eval(result, env, ctx);
        newCtx = this.bind(vtype, payloadr[0], ctx);
        ([err, result] = this.check(payloadr[2], uVal, newCtx));
        if (err) break;
        vtype = uVal;
        tm = term(PI, [payloadr[0], dom, result]);
        result = [vtype, tm];
        break;
      case RLET:
        newCtx = ctx;
        const lnames = [], types = [], terms = [];
        for (let i = 0; i < payloadr[0].length; i++) {
          lnames.push(payloadr[0][i]);
          ([err, result] = this.check(payloadr[1][i], uVal, newCtx));
          if (err) break;
          types.push(result);
          const type = result,
                cvtype = this.eval(type, newCtx[1], newCtx);
          ([err, result] = this.check(payloadr[2][i], cvtype, newCtx));
          if (err) break;
          tm = result;
          terms.push(tm);
          newVal = this.eval(tm, newCtx[1], newCtx);
          newCtx = this.define(newVal, cvtype, payloadr[0][i], newCtx);
        }
        if (err) break;
        ([err, result] = this.infer(payloadr[3], newCtx));
        if (err) break;
        ([vtype, tm] = result);
        tm = term(LET, [lnames, types, terms, tm]);
        result = [vtype, tm];
        break;
      case RHOLE:
        const vMeta = this.freshMeta(ctx);
        vtype = this.eval(vMeta, env, ctx);
        tm = this.freshMeta(ctx);
        result = [vtype, tm];
    }
    return [err, result]
  }

  doElab = ({ data: rterm }) => {
    this.reset();
    // local context: [int lvl, value[] env, str[] names, value[] vtypes, bool[] bds]
    const [err, result] = this.infer(rterm, [0, [], [], [], []]);
    if (err) return [err, this.displayError(result)];
    else return [err, result]
  }
  returnAll = ([vtype, term]) => {
    const ctx = [0, [], [], [], []],
          finalVal = this.eval(term, [], ctx),
          finalTerm = this.quote(finalVal, 0, ctx),
          finalType = this.quote(vtype, 0, ctx),
          metaCtx = [];
    for (let i = 0; i < this.#metas.length; i++) {
      let [mvar, soln] = this.#metas[i];
      if (soln !== null) soln = this.quote(soln, 0, ctx.slice());
      const entry = metaentry(mvar, soln);
      metaCtx.push(entry)
    }
    return [ finalTerm, finalType, term, metaCtx ]  // [ term, type, elab, metas ]
  }
  displayError = errmsg => errmsg

  constructor (state) {
    this.#source = state.source;
    this.run = () => {
      const [err, result] = this.doElab(state);
      if (err) return [err, result];
      else return [err, this.returnAll(result)]
    }
  }
}

function value (id, payload) {
  return [id, structuredClone(payload)]
}

function term (id, payload) {
  return [id, structuredClone(payload)]
}

function metaentry(mvar, soln) {  // Is mvar redundant here?
  return [mvar, soln]
}

export async function evaluate(state) {
  return new EvaluateHoles(state).run()
}