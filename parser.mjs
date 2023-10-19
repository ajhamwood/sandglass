// Minimal thenable
export class Result {
  constructor (fn) {
    let thrown = false, value;
    const
      error = v => (thrown = true, v),
      join = (fn, v = value) => {
        value = fn(v, error);
        if (!Result.prototype.isPrototypeOf(value)) return;
        const r = value.unwrap();
        value = "ok" in r ? r.ok : error(r.err)
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
// - Whitespace label must be first in array
export class Parser {
  #labels = []
  #pos = [[1, 0], [1, 0]]

  // Monadic functions
  seq = ps => state => ps.reduce((acc, p) => acc.then(p), Result.pure(state))
  do = ps => state => ps.reduceRight((acc, p) => (...ss) => p(...ss).then(s => acc(...ss, s)))(state)
  mapFull = (p, fn) => state => p(state).then(fn)

  // Data functions
  reql = (p1, p2) => state => p1(state).then(s1 => p2({ ...s1, data: state.data }))
  reqr = (p1, p2) => state => p1(state).then(s1 => p2(s1).then(s2 => ({ ...s2, data: s1.data })))
  map = (p, fn) => state => p(state).then(s => ({ ...s, data: fn(s.data) }))

  // Error/failure functions
  cut = (p, msg) => state => p(state)
    .catch(({ errmsg, error }, err) => err({
      ...state, error: true,
      errmsg: error ? errmsg + (typeof msg === "undefined" ? "" : `\n${msg}`) : msg
    }))
  peek = p => state => p(state)
    .catch(({ errmsg }, err) => err({ ...state, error: !!state.error, errmsg: state.error ? state.errmsg : errmsg }))
  alt = (p1, p2) => state => p1(state)
    .catch(({ errmsg, error }, err) => error ? err({ ...state, errmsg }) : p2(state))
  choice = ps => state => ps.reduce((acc, p) => this.alt(acc, p))(state)
  option = p => state => this.alt(p, Result.pure)(state)
  
  many = (p, zero = false) => {
    const loop = (s1, res) => p(s1)
      .then(s2 => loop(s2, res.concat([s2.data])))
      .catch(({ errmsg, error }, err) => (zero || res.length) && !error ?
        ({ ...s1, data: res }) : err({ ...s1, errmsg, error }))
    return state => loop(state, [])
  }
  guard = (p, pred, { errmsg, error } = {}) => state => p(state)
    .then((s, err) => pred(s.data) ? s : err({ ...state, error, errmsg: errmsg ?? "Guard" }))

  // Labelling functions
  withLabel = (currentLabel, p) => state => {
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
  relabel = (p, newLabel) => state => {
    const start = state.offset;
    return p(state).then(({ region: { label, labelling }, ...s }) => ({
      ...s, region: { label, labelling: labelling.substring(0, start) + labelling.substring(start)
        .replace(/[\d\w]/g, $1 => $1 == "0" ? "0" : this.#labels.findIndex(x => x === newLabel).toString(36)) }
    }))
  }

  // Position functions
  setPos = ({ start = this.#pos[0], end = this.#pos[1] }) => {
    this.#pos = [start.slice(), end.slice()];
    return [start, end]
  }
  getPos = () => this.#pos

  // Parser state functions
  any = ({ source, region: { label, labelling }, offset, pos: [row, col], data }) =>
    new Result((ok, err) => offset >= source.length ?
      err({ source, region: { label, labelling }, offset, pos: [row, col], data, errmsg: "Any char", error: false }) :
      ok({
        source, offset: offset + 1, data: source[offset],
        region: {
          label, labelling: labelling.substring(0, offset) + this.#labels.findIndex(x => x === label).toString(36) + labelling.substr(offset + 1)
        },
        pos: /\r\n?|\n/g.test(source[offset]) ? [row + 1, 1] : [row, col + 1]
      }))
  eof = ({ source, region, offset, pos, data }) =>
    new Result((ok, err) => offset < source.length ?
      err({ source, region, offset, pos, data, errmsg: "EOF", error: false }) :
      ok({ source, region, offset, pos, data: "" }))
  satisfy = (pred, { error, errmsg } = {}) => this.peek(state => this.any(state)
    .then((s, err) => pred(s) ? s : err({ ...s, error, errmsg: errmsg ?? "Satisfy" })))
  scan = pred => state => this.seq([
    this.many(s1 => this.any(s1).then((s2, err) => pred(s2) ? err({ ...s2, error: false }) : s2)),
    this.alt(this.satisfy(pred), this.eof) ])(state)

  constructor ({ labels = [] } = {}) {
    this.#labels = labels;
    return this
  }

}