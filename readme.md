## Sandglass - a proof assistant on a microcontroller

This is a personal project running from today 23 Sep 2025 until ~31 Oct while I take CSSE2010 Intro to Computer Systems at University of Queensland. The goal is to take a dependently typed functional programming language, design a binary format for it to be compiled into, write a bootloader for the ATmega324A that can save to flash memory, delete, and evaluate those programs with input, and a CLI that can interact with it.

## Development plan

### ```Language design```
  - [ ] Text format for coding
  - [ ] Working model in JS - glued evaluation
  - [ ] Binary format for transmitting/saving
  - [ ] Runtime format for running
  - [ ] Working model in JS - glued eval with holes

### ```Bootloader```
  - [x] Serial comms
  - [ ] Save to application memory, load to runtime format in data memory
  - [ ] Performs glued evaluation (runs) on received params
  - [ ] Glued evaluation with holes

### ```CLI```
  - [x] Serial comms
  - [ ] Controls bootloader - list, eval, load, delete
  - [ ] Binary format to text format (pretty print)