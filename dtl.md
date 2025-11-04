# Sandglass language

Will borrow wholesale from Andras Kovacs' [Elaboration zoo](http://here.com).

## Text format

```
-- Glued evaluation
--   Let expressions:
let-expr  = "let" term-name "=" term ";" (let-expr | term)

--   Functions:
term      = "\" var-name {var-name} "." term

--   Function application:
term      = term term

--   Parentheses:
term      = "(" term ")"


-- Glued evaluation with holes
--   Let expressions:
let-expr  = "let" term-name ":" type-term "=" term ";" (let-expr | term)

--   Types:
type-term = (type-term | "(" term-name ":" type-term ")") ["->" type-term]

--   Functions:
term      = "\" var-name {var-name} "." term

--   Function application:
term      = term term

--   Parentheses:
term      = "(" term ")"
```

## Binary format

```
-- Glued evaluation
--   Module
module = [ signature, len(sections), ...sections ]
                                      -- One module per binary
                                      -- len() : VarUint16 format is exactly enough!

--   Sections
section = [ section_id, len(data), ...data ]
top_names = section(0, len(names), ...names)
local_names = section(1, len(names), ...names)
term_table = [len(terms), ...terms]   -- app len(terms) = len/4, lam len(terms) = len/3, let no div
terms = section(2, len(term_tables), ...term_tables)
                                      -- Order of tables: app terms; lam terms; let terms
defns = section(3, len(term_refs), ...term_refs)
                                      -- Each defn corresponds to a top_name
result = section(4, term_ref)

--   Names
name = [ ...chars ]

--   Terms
app_term = [ term_ref, term_ref ]
lam_term = [ name_ref, term_ref ]        -- Name in local_names
let_term = [ len(name_refs) =:= len(term_refs), ...name_refs, ...term_refs, term_ref ]
                                      -- Names in local_names, each name corresponds to a term
                                      --   (other than result term)

-- Term refs
term_ref = [ term_id, index ] -- term_id: top=0, loc=1, else=term_table index + 2
```

## Runtime structures

```
-- Memory structure
names = [ len(names), ...names ]
spines = [ len(spines), ...spines ]
top_env = [ len(*names), ...*names, len(values), ...values ]
                                      -- Each name corresponds to a value

-- Memory items
name = [ ...chars ]
spine = [ len(values), ...values ]
value = [ value_id, len(data), ...data ]
lam_value = value(0, *name, term, local_env)
loc_value = value(1, *name, *spine)
top_value = value(2, *name, value, *spine)
local_env = [ len(*names), ...*names, len(values), ...values ]
                                      -- Each name corresponds to a value
```