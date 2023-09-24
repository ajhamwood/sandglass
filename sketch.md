## Compiled format - sketch

```
module = [signature, ...sections]  -- one of each  
section = [section_id, section.length, payload]

topname_section = section(0, [...names])     -- uint8 address space  
locname_section = section(1, [...names])     -- uint8 enough?  
defn_section = section(2, [...terms], term)  -- uint8 address space

name = [...chars]  -- how long? 64?

term = [term_id, payload]

loc_term = term(0, [name(uint8)])  -- local_name table  
top_term = term(1, [name(uint8)])  -- top_name table  
app_term = term(2, [term, term])  
lam_term = term(3, [name, term])  
let_term = term(4, [...name(uint8)s], [...terms], term)  
  -- same length, locnames
```

## Runtime structures

```
spine = [...values]  
value = [value_id, data]  
lam_value = value(0, [fn(val -> val)])  
loc_value = value(1, [name, spine])  
top_value = value(2, [name, value, spine])
```

## I/O

  Flash hardware  
=> Check EEPROM for signature  
=> - if EEPROM contains a program, parse it into SRAM - how many parameters?  
=> - if not, await an upload request over UART, to parse into SRAM - what protocol?  
=> Await command over UART  
=> - if evaluate raises error, send error  
=> - if not:  
=> - - if write output, write to screen  
=> - - if port output, do that  
=> - - if memory operations, hmmm...  
=> - if elaborate/metacontext/etc  
=> - - examine output format (same as compiled format?), or  
=> - - pretty print  
=> - if save  
=> - - overwrite to EEPROM, or  
=> - - cancel

sandglass.hex states:
- flash -> has EEPROM program -> load -> ready for command
- flash -> no EEPROM program -> read for loading

```
    sandglass.py
        --compile file.sg
        -c [FILE] :: compile to transmissible format
        --save
        -s :: save to EEPROM
        --port /dev/tty
        -p [PORT] :: port for communication
        --baud 9600
        -b [BAUD_RATE] :: baud rate
        --frame 8:N:1
        -f [BYTESIZE]:[PARITY]:[STOPBITS] :: serial frame format
        --command
        -d [COMMAND] :: send command (elaborate; evaluate; run)
        --write stdout
        -w [FILE] :: write output to file/stdout/stderr
        --pretty
        -r :: pretty print
```
```
    sandglass.s
        1. Await request from sandglass.py:
            * Program upload, or
            * Check EEPROM for program
        2A. Program upload requested:
            1. Send "awaiting-bytes" signal
            2. Load bytes into EEPROM until EOF signal
            3. Send "upload-complete" signal
            4. Await command
        2B. Check EEPROM for program requested:
            1. Read first byte of EEPROM
                * It's equal to signature, or
                * It isn't
            2A. Program is in EEPROM:
                1. Load program parameters
                2. Send "program-ready" signal with basic metadata
                3. Await command
            2B. Program isn't in EEPROM:
                1. Send "no-program" signal
                2. Return to 1.
        3. Await command from sandglass.py
            ... (depends on which type theory I use)
```

## Grammar

First, basic glued eval:  
Top/Loc from token set  
name = \loc loc. expr  
main = expr  
names used in expressions must come from earlier defns  
main must be last "defn"

## DT version

Monadic/algebraic effects? Modal effects?