// Template string utility
function dedent(callSite, ...args) {
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


// Minimal thenable
class Result {
  constructor (fn) {
    let thrown = false, value;
    const
      error = v => (thrown = true, v),
      join = (fn, v = value) => {
        value = fn(v, error);
        if (Result.prototype.isPrototypeOf(value)) {
          const r = value.unwrap();
          value = "ok" in r ? r.ok : error(r.err)
        }
      };

    // On resolve
    this.then = fn => (thrown || join(fn), this);
    
    // On reject
    this.catch = fn => (thrown && (thrown = false, join(fn)), this);
    
    // Await
    this.unwrap = () => ({ [thrown ? "err" : "ok"]: value });
    
    this.toPromise = () => new Promise((ok, err) => this.then(s => ok(s)).catch(e => err(e)));
    return fn(v => join(() => v), e => join(() => error(e)))
  }

  // Resolve
  static pure (v) { return new Result(r => r(v)) }
  
  // Reject
  static throw (e) { return new Result(({}, l) => l(e)) }
}


// Generic parser combinators
class Parser {

  // Monadic functions
  static seq (ps) { return state => ps.reduce((acc, p) => acc.then(p), Result.pure(state)) }
  static do (ps) { return state => ps.reduceRight((acc, p) => (...ss) => p(...ss).then(s => acc(...ss, s)))(state) }
  static mapFull (p, fn) { return state => p(state).then(fn) }

  // Data functions
  static reql (p1, p2) { return state => p1(state).then(s1 => p2({ ...s1, data: state.data })) }
  static reqr (p1, p2) { return state => p1(state).then(s1 => p2(s1).then(s2 => ({ ...s2, data: s1.data }))) }
  static map (p, fn) { return state => p(state).then(s => ({ ...s, data: fn(s.data) })) }

  // Error/failure functions
  static cut (p, msg) {
    return state => p(state)
      .catch(({ errmsg, error }, err) => err({
        ...state, error: true,
        errmsg: error ? errmsg + (typeof msg === "undefined" ? "" : `\n${msg}`) : msg
      }))
  }
  static peek (p) {
    return state => p(state)
      .catch(({ errmsg }, err) => err({ ...state, error: !!state.error, errmsg: state.error ? state.errmsg : errmsg }))
  }
  static alt (p1, p2) {
    return state => p1(state)
      .catch(({ errmsg, error }, err) => error ? err({ ...state, errmsg }) : p2(state))
  }
  static choice (ps) { return state => ps.reduce((acc, p) => Parser.alt(acc, p))(state) }
  static option (p) { return state => Parser.alt(p, Result.pure)(state) }
  
  static many (p, zero = false) {
    const loop = (s1, res) => p(s1)
      .then(s2 => loop(s2, res.concat([s2.data])))
      .catch(({ errmsg, error }, err) => (zero || res.length) && !error ?
        ({ ...s1, data: res }) : err({ ...s1, errmsg, error }))
    return state => loop(state, [])
  }
  static guard (p, pred, { errmsg, error } = {}) {
    return state => p(state)
      .then((s, err) => pred(s.data) ? s : err({ ...state, error, errmsg: errmsg ?? "Guard" }))
  }

  // Parser state functions
  static any ({ source, region: { label, labelling }, offset, pos: [row, col], data }) {
    return new Result((ok, err) => offset >= source.length ?
      err({ source, region: { label, labelling }, offset, pos: [row, col], data, errmsg: "Any char", error: false }) :
      ok({
        source, offset: offset + 1, data: source[offset],
        region: {
          label, labelling: labelling.substring(0, offset) + labels.findIndex(x => x === label) + labelling.substr(offset + 1)
        },
        pos: /\r\n?|\n/g.test(source[offset]) ? [row + 1, 1] : [row, col + 1]
      }))
  }
  static eof ({ source, region, offset, pos, data }) {
    return new Result((ok, err) => offset < source.length ?
      err({ source, region, offset, pos, data, errmsg: "EOF", error: false }) :
      ok({ source, region, offset, pos, data: "" }))
  }
  static satisfy (pred, { error, errmsg } = {}) {
    return Parser.peek(state => Parser.any(state)
      .then((s, err) => pred(s) ? s : err({ ...s, error, errmsg: errmsg ?? "Satisfy" })))
  }
  static scan (pred) {
    return state => Parser.seq([
      Parser.many(s1 => Parser.any(s1).then((s2, err) => pred(s2) ? err({ ...s2, error: false }) : s2)),
      Parser.alt(Parser.satisfy(pred), Parser.eof) ])(state)
  }

}


// Shared context
const globalContext = {
  source: "",
  pos: null,
  labelling: ""
};

// Source string region labels
const labels = [
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
];

// AST
const
// Presyntax:
  RVAR   = 0,
  RLAM   = 1,
  RAPP   = 2,
  RU     = 3,
  RPI    = 4,
  RLET   = 5,
  RHOLE  = 6;

function rawterm (id, payload) {
  return [id, payload]
}

// function setPos
function setPos ({ start = globalContext.pos[0], end = globalContext.pos[1] }) {
  globalContext.pos = [start.slice(), end.slice()];
  return [start, end]
}

function withLabel (currentLabel, p) {
  return state => {
    const { label } = state.region;
    state.region.label = currentLabel;
    return p(state)
      .then(s => {
        s.region.label = label;
        return s
      })
      .catch((e, err) => {
        e.region.label = label;
        return err(e)
      })
  }
}

function relabel (p, newLabel) {
  return state => {
    const start = state.offset;
    return p(state).then(({ region: { label, labelling }, ...s }) => ({
      ...s, region: { label, labelling: labelling.substring(0, start) + String(labels.findIndex(x => x === newLabel)).repeat(s.offset - start) }
    }))
  }
}

function satisfy (pred, { errmsg } = {}) {
  return state => state.error ? Result.throw(state) : Parser.peek(
    s => Parser.any(s)
      .then((t, err) => !/[a-zA-Z_0-9\(\)\{\}:=;\\.\-> \r\n]/.test(t.data) ? { ...t, errmsg: "illegal" } :
        pred(t) ? t : err({ ...t, error: false, errmsg: errmsg ?? "Satisfy" })))(state)
      .then((s, err) => {
        if (s.errmsg === "illegal") {
          setPos({ start: state.pos, end: s.pos });
          return err({ ...state, pos: s.pos, error: true, errmsg: `Found illegal character "${s.data}"` })
        } else return s
      }
  )
}

function cut (p, msg, newPos) {
  return state => p(state)
    .catch(e => {
      if (!e.error) setPos(newPos ?? { start: state.pos, end: e.pos });
      return Parser.cut(
        Result.throw,
        e.error ? e.errmsg : msg
      )(e)
    })
}

function ws (state) {
  // console.log("whitespace", state)
  return withLabel(
    "ws",
    Parser.many(
      Parser.choice([
        Parser.satisfy(s => /[^\S\r\n]/g.test(s.data), { error: false, errmsg: "HWS" }),
        Parser.satisfy(s => /\r\n?|\n/g.test(s.data), { error: false, errmsg: "VWS" }),
        Parser.seq([
          symbol("--", false),
          Parser.scan(s => /\r\n?|\n/g.test(s.data))
        ]),
        Parser.seq([
          symbol("{-", false),
          Parser.many(
            Parser.seq([
              Parser.scan(s => s.data === "-"),
              Parser.satisfy(s => s.data !== "}")
            ]),
            true
          ),
          Parser.scan(s => s.data === "-"),  // To improve this, use continuations?
          Parser.satisfy(s => s.data === "}", { error: false, errmsg: "Multiline comment" })
        ])
      ])
    )
  )(state)
}

function parens (p) {
  return withLabel(
    "encl",
    Parser.do([
      keyword("("),
      ({}, t) => p(t),
      (s, t, u) => Parser.seq([
        cut(
          keyword(")"),
          "Unclosed parens",
          { start: s.pos, end: t.pos }
        ),
        v => ({ ...v, data: u.data })
      ])(u)
    ])
  )
}

function symbol (str, isTest = true) {
  return state => Parser.map(
    Parser.guard(
      Parser.many(
        (isTest ? satisfy : Parser.satisfy)(s => s.data === str[s.offset - state.offset - 1], { error: true, errmsg: `Symbol: "${str}"` })
      ),
      data => data.length === str.length
    ),
    data => data.join("")
  )(state)
}

function catchSymbol (p) {
  return state => p(state)
    .catch((s, err) => !s.error ? err(s) :
      Parser.mapFull(
        Parser.many(
          Parser.satisfy(t => /[^ \r\n]/.test(t.data))
        ),
        t => {
          setPos({ start: s.pos, end: t.pos });
          return err({ ...t, data: t.data.join(""), error: true, errmsg: s.errmsg })
        }
      )(s))
}

function keyword (str, space = false) {
  return state => Parser.seq([
    symbol(str),
    s => (space ? ws : Parser.option(ws))(s)
      .then(t => {
        setPos({ start: state.pos, end: s.pos });
        return { ...t, data: s.data }
      })
  ])(state)
}

function ident (state) {
  return withLabel(
    "ident",
    Parser.reqr(
      catchSymbol(
        Parser.seq([
          satisfy(s => /[a-zA-Z_]/.test(s.data)),
          Parser.do([
            Parser.many(
              satisfy(s => /[a-zA-Z_0-9]/.test(s.data)),
              true  // Allow zero matches
            ),
            (s, t) => {
              setPos({ start: state.pos, end: t.pos });
              return { ...t, data: s.data + t.data.join("") }
            }
          ])
        ])
      ),
      Parser.option(ws)
    )
  )(state)
}

function atom (state) {
  return withLabel(
    "atom",
    Parser.choice([
      Parser.map(keyword("U"), () => rawterm(RU, [])),
      Parser.map(keyword("_"), () => rawterm(RHOLE, [])),
      Parser.mapFull(
        Parser.guard(
          ident,
          data => !~["let", "U", "_"].findIndex(x => x === data)
        ),
        s => {
          setPos({ start: state.pos });
          return { ...s, data: rawterm(RVAR, [s.data]) }
        }
      ),
      parens(term)
    ])
  )(state)
}

function binder (state) {
  return Parser.map(
    catchSymbol(
      Parser.alt(
        ident,
        keyword("_")
      )
    ),
    data => [ data, globalContext.pos ]
  )(state)
}

function spine (state) {
  return Parser.map(
    Parser.many(
      atom
    ),
    data => {
      setPos({ start: state.pos });
      return data.reduce((acc, a) => rawterm(RAPP, [acc, a]))
    }
  )(state)
}

function lam (state) {
  return withLabel(
    "lam",
    Parser.do([
      keyword("\\"),
      ({}, t) => {
        state.region.label = "lamBinder";
        return Parser.many(
          relabel(
            binder,
            "lamBinder"
          )
        )(t)
      },
      (s, t, u) => Parser.seq([
        cut(
          keyword("."),
          "Lambda without body",
          { start: s.pos, end: t.pos }
        ),
        term
      ])(u),
      ({}, {}, u, v) => ({ ...v, data: u.data.reduceRight((acc, [b, pos]) => {
        setPos({ start: pos[1] });
        return rawterm(RLAM, [b, acc])
      }, v.data) })
    ])
  )(state)
}

function namedPi (state) {
  return withLabel(
    "pi",
    Parser.seq([
      Parser.many(
        parens(
          Parser.seq([
            Parser.many(
              relabel(
                binder,
                "piBinder"
              )
            ),
            Parser.do([
              Parser.seq([
                keyword(":"),
                term
              ]),
              (s, t) => ({ ...t, data: s.data.map(([b, pos]) => [b, t.data, [ pos[0], t.pos ]]) })
            ])
          ])
        )
      ),
      Parser.do([
        Parser.seq([
          cut(
            catchSymbol(
              keyword("->")
            ),
            "Expected function type arrow"
          ),
          term
        ]),
        (s, t) => ({ ...t, data: s.data.flat(1).reduceRight((acc, [b, tm, pos]) => {
          setPos({ start: pos[0] })
          return rawterm(RPI, [b, tm, acc])
        }, t.data) })
      ])
    ])
  )(state)
}

function anonPiOrSpine (state) {
  return withLabel(
    "pi",
    Parser.seq([
      cut(
        spine,
        "Malformed spine",
        {}
      ),
      Parser.option(
        Parser.do([
          Parser.reql(
            keyword("->"),
            cut(
              catchSymbol(
                term
              ),
              "Malformed term",
              {}
            )
          ),
          (s, t) => {
            setPos({ start: state.pos });
            return { ...t, data: rawterm(RPI, ["_", s.data, t.data]) }
          }
        ])
      )
    ])
  )(state)
}

function let_ (state) {
  return withLabel(
    "let",
    Parser.do([
      Parser.many(
        Parser.seq([
          keyword("let", true),
          cut(
            Parser.map(binder, ([b]) => b),
            "Malformed binder",
            {}
          ),
          Parser.do([
            Parser.seq([
              cut(
                keyword(":"),
                'Let missing ":"'
              ),
              term
            ]),
            ({}, t) => Parser.seq([
              cut(
                keyword("="),
                'Let missing "="'
              ),
              term
            ])(t),
            (s, t, u) => Parser.seq([
              cut(keyword(";"), 'Let missing ";"'),
              v => ({ ...v, data: [s.data, t.data, u.data] })
            ])(u)
          ])
        ])
      ),
      ({}, t) => term(t),
      ({}, t, u) => ({
        ...u,
        data: rawterm(RLET, [
          ...t.data[0].reduce((ac1, _, i) => ac1.concat([t.data.reduce((ac2, ar) => ac2.concat([ar[i]]), [])]), []),
          u.data
        ])
      })
    ])
  )(state)
}

function term (state) {
  return Parser.choice([
    lam,
    let_,
    namedPi,
    anonPiOrSpine
  ])(state)
}


// Parser entry point
export function parse (source) {
  globalContext.source = source;
  globalContext.pos = [[1, 0], [1, 0]];
  return Result.pure({
    source,
    region: {
      label: "ws",
      labelling: ""
    },
    offset: 0,
    pos: [1, 0],
    data: null
  }).then(program)
    .toPromise()
}

// Parse a program
function program (state) {
  return Parser.seq([
    Parser.option(ws),
    cut(
      Parser.do([
        term,
        ({}, t) => Parser.option(ws)(t),
        ({}, {}, u) => Parser.eof(u),
        ({}, t) => t
      ]),
      "No expression found"
    )
  ])(state)
    .catch(displayError)
    .then(state => {
      globalContext.labelling = state.region.labelling;
      globalContext.data = state.data;
      delete globalContext.pos;
      Object.freeze(globalContext);
      return globalContext
    })
}

// Generate a parser error message
// TODO: multiline?
function displayError ({ errmsg, error }, reject) {
  let lines = globalContext.source.split(/\r\n?|\n/);
  return reject({
    message: dedent`
      ${error ? "Unmanaged p" : "P"}arser error: ${errmsg}
      ${lines[globalContext.pos[0][0] - 1]}
      ${"-".repeat((globalContext.pos[0][1] || 1) - 1)}${
        "^".repeat((globalContext.pos[1][1] - globalContext.pos[0][1]) || 1)} ${
        globalContext.pos.join("-")}`
  })
}
