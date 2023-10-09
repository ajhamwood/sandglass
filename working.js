// Adapted from https://github.com/AndrasKovacs/elaboration-zoo/blob/master/GluedEval.hs

const
    RLOC = 0,
    RTOP = 1,
    RAPP = 2,
    RLAM = 3,
    RLET = 4,

    LOC = 0, // ix
    TOP = 1, // lvl
    APP = 2,
    LAM = 3,
    LET = 4,

    VLAM = 0,
    VLOC = 1,
    VTOP = 2,

    NameEnv = [], //topnames ++ localnames
    TermEnv = []; //topterms? => namenv.len >= termenv.len

function term (id, payload) {
    return [id, payload]
}

function precParens (there, here, string) {
    return there > here ? `(${string})` : string
}

function rawtermstr ([rterm_id, payload], prec = 0) {
    switch (rterm_id) {
        case RLOC: return `RLoc ${payload[0]}`
        case RTOP: return `RTop ${payload[0]}`
        case RAPP: return precParens(prec, 1, `${rawtermstr(payload[0], 1)} :@: ${rawtermstr(payload[1], 2)}`)
        case RLAM: return precParens(prec, 0, `RLam ${payload[0]}. ${rawtermstr(payload[1])}`)
        case RLET: return payload[0].length == 1 ? rawtermstr(payload[2]) :
            precParens(prec, 0, `RLet ${payload[0][0]} = ${rawtermstr(payload[1][0])};\n` +
            `${rawtermstr(term(RLET, [payload[0].slice(1), payload[1].slice(1), payload[2]]))}`)
    }
}

function lamstr (names, name, [body_tid, body_payload]) {
    let res;
    const ns = names.concat([name]);
    if (body_tid !== LAM) res = `. ${termstr(ns, payload[1], 0)}`;
    else {
        const n = fresh(ns, body_payload[0]);
        res = ` ${n}${lamstr(ns, n, body_payload[1])}`;
    }
    return res
}
function termstr (names, [term_id, payload], prec = 0) {
    switch (term_id) {
        case LOC:
            let lvl = names.length - payload[0] - 1;
            return lvl >= names.length ? `@` + payload[0] :
                lvl >= 0 ? names[lvl] : `#${-1 - lvl}`
        case TOP: return NameEnv[payload[0]]
        case APP: return precParens(prec, 1, `${termstr(payload[0], 1)} ${termstr(payload[1], 2)}`)
        case LAM:
            let name = fresh(names, payload[0]);
            return precParens(prec, 0, `\\${payload[0]}. ${lamstr(names, name, payload[1])}`)
        case LET: return payload[0].length == 1 ? termstr(payload[2]) :
            precParens(prec, 0, `let ${payload[0][0]} = ${termstr(payload[1][0])};\n` +
            `${termstr(term(LET, [payload[0].slice(1), payload[1].slice(1), payload[2]]))}`)
    }
}

function value (id, payload) {
    return [id, payload]
}

function concat ([nenv, senv], n, s) {
    return [nenv.concat([n]), senv.concat([s])]
}

function lookup (n, env) { // (value or term) | undefined
    group(() => ["lookup", n, env]);
    let result = env[1][env[0].indexOf(n)];
    ungroup();
    return result
}

function cut (mb) {
    if (typeof mb === undefined) throw 'Not found';
    else return mb
}

function eval (env, [term_id, payload]) {
    group(() => ["eval", topenv, localenv, term_id, payload, "\n", termstr([term_id, payload])]);
    let result;
    switch (term_id) {
        case LOC: //loc payload: debruijn index
        result = cut(lookup(payload[0], env));
        break;
        case TOP: //top payload: top_names level, lazy value somehow??
        result = value(VTOP, [payload[0], cut(lookup(payload[0], env)), []]);
        break;
        case APP: //app payload: fn term, arg term
        result = vapp(eval(topenv, localenv, payload[0]), eval(topenv, localenv, payload[1]));
        break;
        case LAM: //lam payload: binder name, body term, closure environment
        result = value(VLAM, [payload[0], payload[1], env.slice()]);
        break;
        case LET: //let payload: local names, local terms, result term
        result = eval(env.concat([eval(env, payload[1])]),
            payload[0].length == 1 ? payload[2] : term(LET, [payload[0].slice(1), payload[1].slice(1), payload[2]]))
    }
    ungroup();
    return result
}
function vapp ([fn_value_id, payload], arg_value) {
    group(() => ["vapp", fn_value_id, payload, arg_value]);
    let result;
    switch (fn_value_id) {
        case VLAM: //lam payload: name, fn(val -> val)
        result = payload[1](arg_value);
        break;
        case VLOC: //loc payload: name, spine
        result = value(VLOC, [payload[0], payload[1].concat([arg_value])]);
        break;
        case VTOP: //top payload: name, value, spine
        result = value(VTOP, [payload[0], vapp(payload[1], arg_value), payload[2].concat([arg_value])])
    }
    ungroup();
    return result
}

function fresh (localenv, n) {
    group(() => ["fresh", localenv, n]);
    let result;
    switch(lookup(n, localenv)) {
        case undefined: result = n;
        break;
        default: result = fresh(localenv, n + "'")
    }
    ungroup();
    return result
}

function quoteSp (localenv, unfoldtop, tm, spine) {
    group(() => ["quoteSp", localenv, unfoldtop, tm, spine]);
    let result = spine.reduceRight((acc, val) => term(APP, [acc, quote(localenv, unfoldtop, val)]), tm);
    ungroup();
    return result
}

function quote (localenv, unfoldtop, [val_id, payload]) {
    group(() => ["quote", localenv, unfoldtop, val_id, payload]);
    let result;
    switch (val_id) {
        case VLAM: //lam payload: fn(val -> val)
        let nn = fresh(localenv, payload[0]), nv = value(1, [nn, []]);
        result = term(LAM, [nn, quote(concat(localenv, payload[0], nv), unfoldtop, payload[1](nv))]);
        break;
        case VLOC: //loc payload: name, spine
        result = quoteSp(localenv, unfoldtop, term(LOC, [payload[0]]), payload[1]);
        break;
        case VTOP: //top payload: name, value, spine
        result = unfoldtop ?
            quote(localenv, unfoldtop, payload[1]) :
            quoteSp(localenv, unfoldtop, term(TOP, [payload[0]]), payload[2])
    }
    ungroup();
    return result
}

function evalTop (topnames, defns, tm) {
    return eval(topnames.reduce((acc, n, i) => concat(acc, n, eval(acc, [[], []], defns[i])), [[], []]), [[], []], tm)
}

function nfTop (unfoldtop, topnames, defns, main) { //entry point
    return quote([[], []], unfoldtop, evalTop(topnames, defns, main))
}

let topnames = ["zero", "suc", "add", "mul", "5", "10", /*"100"*/],
    defns = [
        term(LAM, ["s", term(LAM, ["z", term(LOC, ["z"])])]),
        term(LAM, ["n", term(LAM, ["s", term(LAM, ["z",
            term(APP, [term(LOC, ["s"]), term(APP, [term(APP, [term(LOC, ["n"]), term(LOC, ["s"])]), term(LOC, ["z"])])])])])]),
        term(LAM, ["a", term(LAM, ["b", term(LAM, ["s", term(LAM, ["z",
            term(APP, [term(APP, [term(LOC, ["a"]), term(LOC, ["s"])]), term(APP, [term(APP, [term(LOC, ["b"]), term(LOC, ["s"])]), term(LOC, ["z"])])])])])])]),
        term(LAM, ["a", term(LAM, ["b", term(LAM, ["s", term(LAM, ["z",
            term(APP, [term(APP, [term(LOC, ["a"]), term(APP, [term(LOC, ["b"]), term(LOC, ["s"])])]), term(LOC, ["z"])])])])])]),
        term(APP, [term(TOP, ["suc"]), term(APP, [term(TOP, ["suc"]), term(APP, [term(TOP, ["suc"]), term(APP, [term(TOP, ["suc"]),
            term(APP, [term(TOP, ["suc"]), term(TOP, ["zero"])])])])])]),
        term(APP, [term(APP, [term(TOP, ["add"]), term(TOP, ["5"])]), term(TOP, ["5"])]),
        // term(APP, [term(APP, [term(TOP, ["mul"]), term(TOP, ["10"])]), term(TOP, ["10"])])
    ],
    // main = term(LET, [
    //     ["five", /*"ten"*/],
    //     [
    //         term(APP, [term(TOP, ["suc"]), term(APP, [term(TOP, ["suc"]), term(APP, [term(TOP, ["suc"]), term(APP, [term(TOP, ["suc"]),
    //             term(APP, [term(TOP, ["suc"]), term(TOP, ["zero"])])])])])]),
    //         // term(APP, [term(APP, [term(TOP, ["add"]), term(LOC, ["five"])]), term(LOC, ["five"])])
    //     ],
    //     term(APP, [term(APP, [term(TOP, ["mul"]), term(LOC, ["five"])]), term(TOP, ["5"])])
    // ]);
    main = term(APP, [term(APP, [term(TOP, ["add"]), term(TOP, ["5"])]), term(TOP, ["5"])]);

    log = fn => console.log.apply(console, fn());
    group = fn => console.group.apply(console, fn());
    ungroup = console.groupEnd;
    // log = group = ungroup = () => {};

console.log("glued: ", termstr(nfTop(false, topnames, defns, main)));
console.log("unglued: ", termstr(nfTop(true, topnames, defns, main)))