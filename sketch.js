// Adapted from https://github.com/AndrasKovacs/elaboration-zoo/blob/master/GluedEval.hs

function term (id, payload) {
    return [id, payload]
}

function precParens (there, here, string) {
    return there > here ? `(${string})` : string
}

function termstr ([term_id, payload], prec = 0) {
    switch (term_id) {
        case 0: return payload[0]
        case 1: return payload[0]
        case 2: return precParens(prec, 1, `${termstr(payload[0], 1)} ${termstr(payload[1], 2)}`)
        case 3: return precParens(prec, 0, `\\${payload[0]}. ${termstr(payload[1])}`)
        case 4: return payload[0].length == 1 ? termstr(payload[2]) :
            precParens(prec, 0, `let ${payload[0].at(-1)} = ${termstr(payload[1].at(-1))};\n\
${termstr(term(4, payload[0].slice(0, -1), payload[1].slice(0, -1), payload[2]))}`)
    }
}

function value (id, payload) {
    return [id, payload]
}

function concat ([nenv, senv], n, s) {
    return [nenv.concat([n]), senv.concat([s])]
}

function lookup (n, env) { // (value or term) | undefined
    group("lookup", n, env);
    let result = env[1][env[0].indexOf(n)];
    ungroup();
    return result
}

function cut (mb) {
    if (typeof mb === undefined) throw 'Not found';
    else return mb
}

function eval (topenv, localenv, [term_id, payload]) {
    group("eval", topenv, localenv, term_id, payload, "\n", termstr([term_id, payload]));
    let result;
    switch (term_id) {
        case 0: //loc payload: local_names index
        result = cut(lookup(payload[0], localenv));
        break;
        case 1: //top payload: top_names index
        result = value(2 /*top*/, [payload[0], cut(lookup(payload[0], topenv)), []]);
        break;
        case 2: //app payload: fn term, arg term
        result = vapp(eval(topenv, localenv, payload[0]), eval(topenv, localenv, payload[1]));
        break;
        case 3: //lam payload: binder name, body term
        result = value(0 /*lam*/, [payload[0], u => eval(topenv, concat(localenv, payload[0], u), payload[1])]);
        break;
        case 4: //let payload: local names, local terms, result term
        result = eval(topenv, concat(localenv, payload[0].at(-1), eval(topenv, localenv, payload[1].at(-1))),
             payload[0].length == 1 ? payload[2] : term(4, [payload[0].slice(0, -1), payload[1].slice(0, -1), payload[2]]))
    }
    ungroup();
    return result
}
function vapp ([fn_value_id, payload], arg_value) {
    group("vapp", fn_value_id, payload, arg_value);
    let result;
    switch (fn_value_id) {
        case 0: //lam payload: name, fn(val -> val)
        result = payload[1](arg_value);
        break;
        case 1: //loc payload: name, spine
        result = value(1, [payload[0], payload[1].concat([arg_value])]);
        break;
        case 2: //top payload: name, value, spine
        result = value(2, [payload[0], vapp(payload[1], arg_value), payload[2].concat([arg_value])])
    }
    ungroup();
    return result
}

function fresh (localenv, n) {
    group("fresh", localenv, n);
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
    group("quoteSp", localenv, unfoldtop, tm, spine);
    let result = spine.reduceRight((acc, val) => term(2, [acc, quote(localenv, unfoldtop, val)]), tm);
    ungroup();
    return result
}

function quote (localenv, unfoldtop, [val_id, payload]) {
    group("quote", localenv, unfoldtop, val_id, payload);
    let result;
    switch (val_id) {
        case 0: //lam payload: fn(val -> val)
        let nn = fresh(localenv, payload[0]), nv = value(1, [nn, []]);
        result = term(3, [nn, quote(concat(localenv, payload[0], nv), unfoldtop, payload[1](nv))]);
        break;
        case 1: //loc payload: name, spine
        result = quoteSp(localenv, unfoldtop, term(0, [payload[0]]), payload[1]);
        break;
        case 2: //top payload: name, value, spine
        result = unfoldtop ?
            quote(localenv, unfoldtop, payload[1]) :
            quoteSp(localenv, unfoldtop, term(1, [payload[0]]), payload[2])
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

let topnames = ["zero", "suc", "add", "mul", "5", "10", "100"],
    defns = [
        term(3, ["s", term(3, ["z", term(0, ["z"])])]),
        term(3, ["n", term(3, ["s", term(3, ["z",
            term(2, [term(0, ["s"]), term(2, [term(2, [term(0, ["n"]), term(0, ["s"])]), term(0, ["z"])])])])])]),
        term(3, ["a", term(3, ["b", term(3, ["s", term(3, ["z",
            term(2, [term(2, [term(0, ["a"]), term(0, ["s"])]), term(2, [term(2, [term(0, ["b"]), term(0, ["s"])]), term(0, ["z"])])])])])])]),
        term(3, ["a", term(3, ["b", term(3, ["s", term(3, ["z",
            term(2, [term(2, [term(0, ["a"]), term(2, [term(0, ["b"]), term(0, ["s"])])]), term(0, ["z"])])])])])]),
        term(2, [term(1, ["suc"]), term(2, [term(1, ["suc"]), term(2, [term(1, ["suc"]), term(2, [term(1, ["suc"]),
            term(2, [term(1, ["suc"]), term(1, ["zero"])])])])])]),
        term(2, [term(2, [term(1, ["add"]), term(1, ["5"])]), term(1, ["5"])]),
        term(2, [term(2, [term(1, ["mul"]), term(1, ["10"])]), term(1, ["10"])])
    ],
    main = term(4, [
        ["five"],
        [term(2, [term(1, ["suc"]), term(2, [term(1, ["suc"]), term(2, [term(1, ["suc"]), term(2, [term(1, ["suc"]),
            term(2, [term(1, ["suc"]), term(1, ["zero"])])])])])])],
        term(2, [term(2, [term(1, ["mul"]), term(0, ["five"])]), term(1, ["5"])])
    ]);

// group = console.group;
// ungroup = console.groupEnd;
group = ungroup = () => {};

console.log("glued: ", termstr(nfTop(false, topnames, defns, main)));
console.log("unglued: ", termstr(nfTop(true, topnames, defns, main)))