function eval (topenv, localenv, [term_id, payload]) {
    switch (term_id) {
        case 0: //loc payload: local_names index
        return fromJust(lookup(payload[0], localenv))
        case 1: //top payload: top_names index
        return value(2 /*top*/, payload[0], spine(), fromJust(lookup(payload[0], topenv)))
        case 2: //app payload: fn term, arg term
        return vapp(eval(topenv, localenv, payload[0]), eval(topenv, localenv, payload[1]))
        case 3: //lam payload: binder name, body term
        return value(0 /*lam*/, payload[0], u => eval(topenv, localenv.concat([[payload[0], u]]), payload[1]))
        case 4: //let payload: local names, local terms, result term
        return eval(topenv, localenv.concat([[payload[0].pop(), eval(topenv, localenv, payload[1].pop())]]), term(4, payload))
    }
}
function vapp ([fn_value_id, payload], arg_value) {
    switch (fn_value_id) {
        case 0: //lam payload: fn(val -> val)
        return payload[0](arg_value)
        case 1: //loc payload: name, ...spine
        return value(1, payload[0], payload.slice(1).push(arg_value))
        case 2: //top payload: name, value, ...spine
        return value(2, payload[0], payload.slice(2).push(arg_value), vapp(payload[1], arg_value))
    }
}

function fresh (localenv, name) {
    switch(lookup(name, localenv)) {
        case null: return name
        default: fresh(localenv, name + "'")
    }
}

function quoteSp (localenv, unfoldtop, term, spine) {
    spine
}