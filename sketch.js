// Adapted from https://github.com/AndrasKovacs/elaboration-zoo/blob/master/GluedEval.hs

const
    LOC = 0,
    TOP = 1,
    APP = 2,
    LAM = 3,
    LET = 4,

    VLAM = 0,
    VLOC = 1,
    VTOP = 2;

    TopEnv = null,
    LocEnv = [[], []];

function term (id, payload) {
    return [id, payload]
}

function precParens (there, here, string) {
    return there > here ? `(${string})` : string
}

function termstr ([term_id, payload], prec = 0) {
    switch (term_id) {
        case LOC: return payload[0]
        case TOP: return payload[0]
        case APP: return precParens(prec, 1, `${termstr(payload[0], 1)} ${termstr(payload[1], 2)}`)
        case LAM: return precParens(prec, 0, `\\${payload[0]}. ${termstr(payload[1])}`)
        case LET: return payload[0].length == 1 ? termstr(payload[2]) :
            precParens(prec, 0, `let ${payload[0][0]} = ${termstr(payload[1][0])};\n\
${termstr(term(LET, [payload[0].slice(1), payload[1].slice(1), payload[2]]))}`)
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
    log(() => ["lookup", result]);
    ungroup();
    return result
}

function cut (mb) {
    if (typeof mb === "undefined") throw 'Not found';
    else return mb
}

function eval (topenv, [term_id, payload]) {
    group(() => ["eval", topenv, LocEnv, term_id, payload, "\n", termstr([term_id, payload])]);
    let result, newval;
    switch (term_id) {
        case LOC: //payload: local_names index
        result = cut(lookup(payload[0], LocEnv));
        break;

        case TOP: //payload: top_names index
        newval = cut(lookup(payload[0], topenv));
        result = value(VTOP, [payload[0], newval, []]);
        break;

        case APP: //payload: fn term, arg term
        let func = eval(topenv, payload[0]),
            arg = eval(topenv, payload[1]);
        result = vapp(func, arg);
        break;

        case LAM: //payload: binder name, body term, closure environment
        result = value(VLAM, [payload[0], payload[1], [LocEnv[0].slice(), LocEnv[1].slice()]]);
        break;

        case LET: //payload: local names, local terms, result term
        newval = eval(topenv, payload[1][0]);
        let newterm;
        if (payload[0].length == 1) newterm = payload[2]
        else {
            let names = payload[0].slice(1),
                values = payload[1].slice(1);
            newterm = term(LET, [names, values, payload[2]]);
        }
        LocEnv[0].push(payload[0][0])
        LocEnv[1].push(newval)
        result = eval(topenv, newterm);
        LocEnv.pop()
        LocEnv.pop()
    }
    ungroup();
    return result
}
function capp ([n, tm, localenv], val) {
    group(() => ["capp", n, tm, localenv, val]);
    localenv[0].push(n);
    localenv[1].push(val);
    let result = eval(localenv, tm);
    localenv.pop();
    localenv.pop();
    ungroup();
    return result
}
function vapp ([fn_value_id, payload], arg_value) {
    group(() => ["vapp", fn_value_id, payload, arg_value]);
    let result, newspine;
    switch (fn_value_id) {
        case VLAM: //payload: name, term, localenv
        result = capp(payload, arg_value);
        break;

        case VLOC: //payload: name, spine
        newspine = payload[1].concat([arg_value])
        result = value(VLOC, [payload[0], newspine]);
        break;

        case VTOP: //payload: name, value, spine
        newspine = payload[2].concat([arg_value]);
        let newval = vapp(payload[1], arg_value);
        result = value(VTOP, [payload[0], newval, newspine]);
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
    let result = tm, arg;
    for (let i = spine.length - 1; i >= 0; i--) {
        arg = quote(localenv, unfoldtop, spine[i]);
        result = term(APP, [result, arg])
    }
    ungroup();
    return result
}

function quote (localenv, unfoldtop, [val_id, payload]) {
    group(() => ["quote", localenv, unfoldtop, val_id, payload]);
    let result;
    switch (val_id) {
        case VLAM: //payload: name, term, localenv
        let nn = fresh(localenv, payload[0]),
            nv = value(VLOC, [nn, []]);
        
        payload[2][0].push(nn);
        payload[2][1].push(nv);
        let apcl = capp(payload[2], nn);
        payload[2][1].pop();
        payload[2][0].pop();

        localenv[0].push(nn);
        localenv[1].push(nv);
        let newbody = quote(localenv, unfoldtop, apcl);
        localenv[0].pop();
        localenv[1].pop();

        result = term(LAM, [nn, newbody]);
        break;

        case VLOC: //payload: name, spine
        result = quoteSp(localenv, unfoldtop, term(LOC, [payload[0]]), payload[1]);
        break;

        case VTOP: //payload: name, value, spine
        result = unfoldtop ?
            quote(localenv, unfoldtop, payload[1]) :
            quoteSp(localenv, unfoldtop, term(TOP, [payload[0]]), payload[2])
    }
    ungroup();
    return result
}

function evalTop (topnames, defns, tm) {
    TopEnv = [[], []];
    for (let i = 0; i < topnames.length; i++) {
        let val = eval(TopEnv, defns[i]);
        TopEnv[0].push(topnames[i]);
        TopEnv[1].push(val)
    }
    let result = eval(TopEnv, tm);
    TopEnv = null;
    return result
}

function nfTop (unfoldtop, topnames, defns, main) { //entry point
    let finalVal = evalTop(topnames, defns, main);
    LocEnv = [[], []];
    let result = quote(LocEnv, unfoldtop, finalVal);
    return result
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