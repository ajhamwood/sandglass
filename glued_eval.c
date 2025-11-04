#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/eeprom.h>
// #include <avr/wdt.h>
// Wiring:
// - LEDs L[7..0]     <-  Port C[7..0]
// - TX, RX           <-> Pin D0, Port D1


// Definitions
#define TRUE 1
#define FALSE 0
#define nop
// #define DEBUG_NBE
#define ARENA_REGION_SIZE 128

#define OUTBUF_SIZE 64
#define INBUF_SIZE 64

#define TX_READY 1
#define TX_SAVEOK 2
#define TX_MEM 3
#define TX_ACK 4
#define TX_RESULT 5
#define TX_MONITOR 6
#define TX_INFO 7

#define TX_MEMERR 63
#define TX_FRAMEERR 62
#define TX_RANGEERR 61
#define TX_NACK 60
#define TX_PGMERR 59
#define TX_NOTFOUND 58

#define RX_SAVE 1
#define RX_DELETE 2
#define RX_EVAL 3
#define RX_PARAM 4
#define RX_RUN 5
#define RX_MEMRQ 6
#define RX_DUMP 7
#define RX_READ 8
#define RX_LIST 9
#define RX_IMMED 10

#define RX_DONE 63
#define RX_DEBUG 127

#define ST_BEGIN 1
#define ST_READY 2
#define ST_WAITING 3
#define ST_SAVE 4
#define ST_DELETE 5
#define ST_APPLY 6
#define ST_EVALING 7
#define ST_RUN 8
#define ST_MEMCNT 9
#define ST_DUMP 10
#define ST_READ 11
#define ST_LIST 12

#define ST_DONE 63
#define ST_DEBUG -1

#define RET_EXIT 1
#define RET_MULTI 2
#define RET_STRING 4
#define RET_BYTECODE 8

// Header //
// Tyepdefs
typedef struct vect {
  uint16_t len;
  void *bytes;
} vect;
typedef struct vect_short {
  uint8_t len;
  void *bytes;
} vect_short;

// Arena allocator
typedef struct region region;
struct region {
  region *next;
  uint16_t brk;
  uint16_t size;
  uintptr_t data[];
};
typedef struct arena {
  region *begin, *end;
} arena;
// static arena term_arena = { 0 };
// static arena value_arena = { 0 };
static arena default_arena = { 0 };
static arena *focus_arena = &default_arena;

// Linked array? what is this called
// data length == 2^level
typedef struct link link;
struct link {
  uint8_t level; // power of two
  link *next;
  uintptr_t data[];
};
typedef struct array {
  size_t size;
  uint8_t len;
  link *begin;
} array;

// Files
struct entry {
  uint64_t *name;
  uint8_t index;
  uint16_t len;
};
struct handle {
  uint8_t index;
  uint8_t len;
  void *bytes;
};
struct file {
  uint64_t *name;
  uint8_t len;
  uint8_t *bytes;
};

// AST //
// Terms
typedef struct term_ref {
  enum { TOP, LOC, APP, LAM, LET } __attribute__ ((__packed__)) id;
  uint8_t ix; // index in canonical array for its term_con
} term_ref;

typedef struct top {
  uint8_t len;
  uint8_t *bytes;
} top;
typedef struct loc {
  uint8_t len;
  uint8_t *bytes;
} loc;
typedef struct app {
  term_ref func;
  term_ref arg;
} app;
typedef struct lam {
  uint8_t index;
  term_ref body;
} lam;
typedef struct let {
  uint8_t index;
  term_ref term;
  term_ref result;
} let;

// Runtime values
typedef struct val_ref {
  enum { VTOP, VLOC, VLAM } __attribute__ ((__packed__)) id;
  uint8_t ix; // index in canonical array for its val_con
} val_ref;
typedef struct ventry {
  vect_short *name; // A top_name or a loc_name
  val_ref value;
} ventry;

typedef struct vtop {
  uint8_t index;
  val_ref value;
  uint8_t sp_ix; // index of pgm.spines
} vtop;
typedef struct vloc {
  vect_short *name;
  uint8_t sp_ix; // index of pgm.spines
} vloc;
typedef struct vlam {
  vect_short *binder;
  term_ref body;
  uint8_t cl_ix; // index of pgm.closures
} vlam;

typedef struct pstate {
  uint8_t unfoldtop;
  // Terms
  vect top_names; // of top
  array loc_names; // of loc
  array apps;  // of app
  array lams; // of lam
  array lets; // of let, TODO lets length will not grow

  vect defns; // of term_ref
  term_ref result;
  // Values
  array topenv; // of ventry
  array vtops; // of vtop
  array vlocs; // of vloc
  array vlams; // of vlam

  array spines; // of array of val_ref
  array closures; // of array of ventry
} pstate;
static pstate pgm;


// Func decs
// UART
static void uart_put_char (uint8_t);
static uint8_t uart_get_char ();
static void uart_write (vect);
static void uart_read (vect);
static void uart_read_short (vect_short);
static void uart_skip (uint8_t);
volatile uint8_t outbuf[OUTBUF_SIZE];
volatile uint8_t outpos;
volatile uint8_t outbytes_left;
volatile uint8_t inbuf[INBUF_SIZE];
volatile uint8_t inpos;
volatile uint8_t inbytes_left;

// CLI comms
static uint16_t get_varuint16 ();
static void put_varuint16 (uint16_t);
static uint16_t eeprom_varuint_to_uint16 (uint8_t*);
static uint8_t varuint_len (uint16_t);
static vect entry_to_vect (struct entry, uint8_t[11]);
static void decimal (uint8_t*, uint8_t);
static size_t get_ram ();
static void set_peak_ram ();
static uint8_t hibit (uint8_t);

// Arena allocator
static region *new_region (size_t);
static void *arena_alloc (size_t);
static void arena_free ();

// Linked array
static array *array_init (array*, size_t);
static void *array_extend (array*);
static void *array_shrink (array*);
static array *array_copy (array*, array*);
static void *array_access (array*, uint8_t);
static uint8_t array_indexof (array*, void*);

// Files on EEPROM
static uint8_t get_pgm_count ();
static void get_pgm_names (vect);
static void get_pgm_data (vect);
static uint8_t get_indexof_pgm (char*);
static uint16_t get_mem ();
static struct handle get_next_handle ();
static struct handle get_handle (uint8_t);
static void fresh_pgm_name (vect);
static struct handle save_file (struct file);
static struct file read_file (uint8_t);

// Commands
static vect summary ();
static uint16_t get_mem ();
static uint8_t find_pgm ();
static uint8_t valid_index (uint8_t);
static struct entry save (uint8_t*);
static uint8_t delete (uint8_t);
static void tell_rangeerr (uint8_t);
static void tell_ram ();
// static void param ();
// Runtime structures
static void parse (uint8_t);
static void parse_immed ();
static void emit ();

// NbE //
static val_ref lookup (vect_short*, array*);
static val_ref eval (term_ref, array*);
static val_ref capp (vlam*, val_ref);
static val_ref vapp (val_ref, val_ref);
static vect_short *fresh (vect_short*, array*);
static term_ref quote (val_ref, array*);
static term_ref quote_sp (term_ref, array*, array*);
static void nf_top ();



// Debug
#ifdef DEBUG_NBE
static void hex (char*, uint8_t);
static void imm_debug (vect, uint8_t);
static char *tids = "TOPLOCAPPLAMLET";
static char *vids = "VTOPVLOCVLAM";
static struct {
  char *test;
  char *lookup, *eval, *capp, *vapp, *fresh, *quote, *quote_sp, *nf_top;
} qs = {
  .test = "t             ",
  .lookup = "\\lookup",
  .eval = "\\eval xxx hh",
  .capp = "\\capp",
  .vapp = "\\vapp xxxx xxxx",
  .fresh = "\\fresh",
  .quote = "\\quote xxxx     ",
  .quote_sp = "\\quote_sp",
  .nf_top = "\\nf_top"
};
#endif
uint8_t indent = 0;
uint8_t debug = 0;
uint16_t test = 0;
uint8_t btn_prev = 0, btn = 0;
  // do {
  //   btn_prev = btn;
  //   btn = PINA & 1;
  // } while (!(btn_prev == 0 && btn == 1));



// Main //
uint16_t peak_ram = 2048;

// CLI comms
uint8_t state = ST_BEGIN;
uint8_t mcnt = 0;
int main () {
  mcnt++;
  // PORTC ^= 0x80;
  // PORTC |= MCUSR;
  uart_put_char(0xFE);

  // Variables
  uint8_t cmd;

  // LEDs
  DDRC = 0xFF;

  // Reset indicator
  TCCR0B = (5 << CS00);
  TIMSK0 |= 1 << TOIE0;
  if (!debug) PORTC = 0x01;

  // UART:
  UBRR0 = 12; // 38400 baud
  UCSR0B = (1 << RXEN0) | (1 << TXEN0) | (1 << RXCIE0);

  sei();

  // Watchdog timer
  if (!debug) {
    MCUSR = 0;
    WDTCSR |= (1 << WDCE); // Change enable
    WDTCSR = (1 << WDE) | (5 << WDP0); // Turn on watchdog
  }
  

  // Begin comms
  
  uint8_t c = uart_get_char();
  if (c == 'U') {
    state = ST_READY;
  } else while (1) if (!debug) PORTC = 0x55; // Must be better way

  vect v_load = summary();
  uart_put_char(TX_READY);
  uart_put_char(((uint8_t*) v_load.bytes)[0]);
  vect v_summary = { .len = v_load.len - 2, .bytes = v_load.bytes + 2 };
  uart_write(v_summary);
  free(v_load.bytes);
  state = ST_WAITING;


  // Listen for commands
  while (1) {
    if (state == ST_WAITING || state == ST_EVALING) {
      cmd = uart_get_char();
      switch (cmd) {
        case RX_DONE:
          state = ST_DONE;
          break;

        case RX_MEMRQ:
          if (state == ST_WAITING) {
            state = ST_MEMCNT;
            uint16_t mem = get_mem();
            cli();
            uart_put_char(TX_MEM);
            put_varuint16(mem);
            sei();
            state = ST_WAITING;
          }
          break;

        case RX_LIST:
          if (state == ST_WAITING) {
            state = ST_LIST;
            uint8_t pgm_count = get_pgm_count();
            uint8_t info[pgm_count * 10];
            vect v_info = { .len = pgm_count * 10, .bytes = info };
            get_pgm_data(v_info);
            cli();
            uart_put_char(TX_INFO);
            uart_put_char(pgm_count);
            uart_write(v_info);
            sei();
            state = ST_DONE;
          }
          break;

        case RX_SAVE:
          if (state == ST_WAITING) {
            state = ST_SAVE;
            uint8_t nameb[8];
            struct entry e_save = save(nameb);
            cli();
            if (e_save.name == 0) {
              uart_put_char(TX_MEMERR);
              put_varuint16(e_save.len);
            } else {
              uint8_t b_save[11];
              vect v_save = entry_to_vect(e_save, b_save);
              uart_put_char(TX_SAVEOK);
              uart_write(v_save);
            }
            sei();
            state = ST_DONE;
          }
          break;

        case RX_READ + 32:
        case RX_READ:
          if (state == ST_WAITING) {
            state = ST_READ;
            uint8_t index = valid_index(cmd);
            if (index == UINT8_MAX) break;
            struct file f_read = read_file(index);
            cli();
            if (f_read.len == 0) {
              uart_put_char(TX_RANGEERR);
              uart_put_char(*((uint8_t*) f_read.name));
            } else {
              vect v_read = { .len = f_read.len - 8, .bytes = f_read.bytes };
              vect v_readname = { .len = 8, .bytes = (uint8_t*) f_read.name };
              uart_put_char(TX_RESULT);
              put_varuint16(v_read.len);
              uart_write(v_readname);
              uart_write(v_read);
            }
            sei();
            state = ST_DONE;
          }
          break;

        case RX_DELETE + 32:
        case RX_DELETE:
          if (state == ST_WAITING) {
            state = ST_DELETE;
            uint8_t index = valid_index(cmd);
            if (index == UINT8_MAX) break;
            uint8_t del_fail = delete(index);
            cli();
            if (del_fail) {
              uart_put_char(TX_RANGEERR);
              uart_put_char(del_fail);
            } else {
              uart_put_char(TX_MEM);
              put_varuint16(get_mem());
            }
            sei();
            state = ST_DONE;
          }
          break;

        case RX_DUMP:
          if (state == ST_WAITING) {
            state = ST_DUMP;
            eeprom_update_word((uint16_t*) 1022, 0xFF00);
            cli();
            uart_put_char(TX_MEM);
            put_varuint16(get_mem());
            sei();
            state = ST_DONE;
          }
          break;

        case RX_EVAL + 32:
        case RX_EVAL:
          if (state == ST_WAITING) {
            state = ST_APPLY;
            pgm.unfoldtop = uart_get_char();
            uint8_t index = valid_index(cmd);
            if (index == UINT8_MAX) break;
            parse(index);
            cli();
            uart_put_char(TX_ACK);
            uart_put_char(RX_EVAL);
            sei();
            state = ST_EVALING;
          }
          break;

        case RX_PARAM:
          if (state == ST_EVALING) {
            state = ST_APPLY;
            // param();
            cli();
            uart_put_char(TX_ACK);
            uart_put_char(RX_PARAM);
            sei();
            state = ST_EVALING;
          }
          break;

        case RX_RUN:
          if (state == ST_EVALING) {
            state = ST_RUN;
            nf_top();
            cli();
            tell_ram();
            uart_put_char(TX_RESULT);
            emit();
            sei();
            state = ST_DONE;
          }
          break;

        case RX_IMMED:
          if (state == ST_WAITING) {
            state = ST_RUN;
            pgm.unfoldtop = uart_get_char();
            parse_immed();
            nf_top();
            cli();
            tell_ram();
            uart_put_char(TX_RESULT);
            emit();
            sei();
            state = ST_DONE;
          }
          break;

        case ((uint8_t) RX_DEBUG):
          if (state == ST_WAITING) {
            state = ST_DEBUG;
            uint8_t flags = RET_EXIT | RET_BYTECODE;
            pgm.unfoldtop = uart_get_char();
            get_varuint16();
            parse(uart_get_char());
            nf_top();
            cli();
            uart_put_char(TX_RESULT);
            uart_put_char(flags);
            emit();
            sei();
            state = flags & RET_EXIT ? ST_DONE : ST_WAITING;
          }

        // case 'U': break;
      }
    } else if (state == ST_DONE) {
      if (!debug) PORTC |= 0x80;
      TIMSK0 |= (1 << TOIE0);
      while(1);
    }
  }
}

ISR (TIMER0_OVF_vect) {
  if (state == ST_DONE && !(outbytes_left || inbytes_left)) {
    TIMSK0 &= ~(1 << TOIE0);
    arena_free();
    if (!debug) PORTC = 0x00;
  } else if (state > ST_WAITING) {
    if (!debug) asm volatile("WDR"::);
    if (!debug) PORTC ^= 0x40;
  } else if (!debug) PORTC &= ~0x01;
}



// UART
static void uart_write (vect out) {
  for (int i = 0; i < out.len; i++) uart_put_char(((uint8_t*) out.bytes)[i]);
}

static void uart_read (vect in) {
  for (int i = 0; i < in.len; i++) ((uint8_t*) in.bytes)[i] = uart_get_char();
}

static void uart_read_short (vect_short in) {
  for (int i = 0; i < in.len; i++) ((uint8_t*) in.bytes)[i] = uart_get_char();
}

static void uart_skip (uint8_t count) {
  for (int i = 0; i < count; i++) uart_get_char();
}

static void uart_put_char (uint8_t c) {
  while (outbytes_left >= OUTBUF_SIZE);
  cli();
  outbuf[outpos++] = c;
  outpos &= OUTBUF_SIZE - 1;
  outbytes_left++;
  UCSR0B |= (1 << UDRIE0);
  sei();
}

static uint8_t uart_get_char () {
  while (inbytes_left == 0);
  cli();
  char c = inbuf[(INBUF_SIZE + inpos - inbytes_left--) & (INBUF_SIZE - 1)];
  sei();
  return c;
}

ISR (USART0_UDRE_vect) {
  if (outbytes_left > 0) UDR0 = outbuf[(OUTBUF_SIZE + outpos - outbytes_left--) & (OUTBUF_SIZE - 1)];
  else UCSR0B &= ~(1 << UDRIE0);
}

ISR (USART0_RX_vect) {
  char c = UDR0;
  inbuf[inpos++] = c;
  inpos &= INBUF_SIZE - 1;
  inbytes_left++;
}



// Utils
static uint16_t get_varuint16 () {
  uint8_t b0 = uart_get_char();
  if ((b0 & 0x80) == 0) return b0;
  uint8_t b1 = uart_get_char();
  return ((b1 << 7) | (b0 & 0x7f));
}
static void put_varuint16 (uint16_t n) {
  if (n >= 0x80) {
    uart_put_char((n & 0x7F) | 0x80);
    uart_put_char(n >> 7);
  } else {
    uart_put_char(n);
  }
}
static uint16_t eeprom_varuint_to_uint16 (uint8_t* ptr) {
  uint8_t b0 = eeprom_read_byte(ptr);
  if ((b0 & 0x80) == 0) return b0;
  uint8_t b1 = eeprom_read_byte(ptr + 1);
  return ((b1 << 7) | (b0 & 0x7f));
}
static uint8_t varuint_len (uint16_t n) {
  return n >= 0x80 ? 2 : 1;
}

static vect entry_to_vect (struct entry e, uint8_t bytes[11]) {
  bytes[0] = e.index;
  *((uint16_t*) (bytes + 1)) = e.len;
  *((uint64_t*) (bytes + 3)) = *((uint64_t*) e.name);
  vect v = { .len = 11, .bytes = bytes };
  return v;
}

static void decimal (uint8_t *bytes, uint8_t n) {
  if (n == 0) return 0;
  *(bytes + 7) = (n % 10) + 0x30;
  if (n < 10) return 1;
  *(bytes + 6) = ((n / 10) % 10) + 0x30;
  if (n < 100) return 2;
  *(bytes + 5) = (n / 100) + 0x30;
}

static size_t get_ram () {
  extern int __heap_start, *__brkval;
	return SP - (size_t) (__brkval == 0 ? &__heap_start : __brkval);
}
static void set_peak_ram () {
  size_t mem = get_ram();
  peak_ram = mem < peak_ram ? mem : peak_ram;
}

// from Hacker's Delight
static uint8_t hibit (uint8_t n) {
  n |= (n >> 1);
  n |= (n >> 2);
  n |= (n >> 4);
  return n - (n >> 1);
}



// Arena allocator
static region *new_region (size_t size) {
  region *r = malloc(sizeof(region) + size);
  r->next = NULL;
  r->brk = 0;
  r->size = size;
  return r;
}
static void *arena_alloc (size_t size) {
  arena *a = focus_arena;
  region *r;
  if (a->end == NULL) {
    a->end = new_region(size > ARENA_REGION_SIZE ? size : ARENA_REGION_SIZE);
    a->begin = a->end;
    r = a->begin;
  } else {
    r = a->begin;
    while (r->brk + size > r->size && r->next) r = r->next;
    if (r->brk + size > r->size) {
      r->next = new_region(size > ARENA_REGION_SIZE ? size : ARENA_REGION_SIZE);
      r = r->next;
      a->end = r;
    }
  }
  void *ptr = (uint8_t*) r->data + r->brk;
  r->brk += size;
  return ptr;
}
static void arena_free () {
  arena *a = focus_arena;
  region *r = a->begin;
  while (r) {
    region *s = r;
    r = r->next;
    free(s);
  }
  a->begin = NULL;
  a->end = NULL;
}



// Linked array
static array *array_init(array *a, size_t size) {
  a->size = size;
  a->len = 0;
  a->begin = NULL;
  return a;
}
static void *array_extend (array *a) {
  uint8_t level = hibit(a->len);
  link *l = a->begin;
  if (l == NULL) {
    l = arena_alloc(sizeof(link) + a->size);
    l->level = 0; // special value
    l->next = NULL;
    a->begin = l;
  } else {
    while (l->level < level && l->next) l = l->next;
    if (a->len >> 1 == l->level) {
      l->next = arena_alloc(sizeof(link) + level * a->size);
      l = l->next;
      l->level = level;
      l->next = NULL;
    }
  }
  return (uint8_t*) l->data + a->size * (a->len++ ^ level);
}
static void *array_shrink (array *a) {
  if (a->len == 0) return NULL;
  uint8_t level = hibit(--a->len);
  link *l = a->begin;
  while (l->level < level && l->next) l = l->next;
  return (uint8_t*) l->data + a->size * (a->len ^ level);
}



// b: zero-length array
static array *array_copy (array *b, array *a) {
  if (a->len == 0) return b;
  link *al = a->begin;
  link *bl = NULL;
  
  size_t cur_len = sizeof(link) + b->size;
  bl = arena_alloc(cur_len);
  memcpy(bl, al, cur_len);
  b->begin = bl;
  
  uint8_t level = 1;
  while (level < a->len) {
    cur_len = sizeof(link) + level * b->size;
    bl->next = arena_alloc(sizeof(link) + level * a->size);
    bl = bl->next;
    al = al->next;
    memcpy(bl, al, cur_len);
    level <<= 1;
  }
  bl->next = NULL;
  b->len = a->len;
  return b;
}
static void *array_access (array *a, uint8_t index) {
  if (index >= a->len) return NULL;
  uint8_t level = hibit(index);
  link *l = a->begin;
  while (l->level < level && l->next) l = l->next;
  return (uint8_t*) l->data + a->size * (index ^ level);
}
// Not found => max uint8_t
static uint8_t array_indexof (array *a, void *item) {
  if (a->len == 0) return UINT8_MAX;
  link *l = a->begin;
  uint8_t cmp;
  uint8_t i = -1;
  do {
    if (++i == 0) l = a->begin;
    else if (i >> 1 == l->level) l = l->next;
    cmp = memcmp(item, l->data + a->size * (i ^ l->level), a->size);
  } while (cmp != 0 && i < a->len - 1);
  if (cmp != 0) return UINT8_MAX;
  else return i;
}



// Files on EEPROM
static uint8_t get_pgm_count () {
  return eeprom_read_byte((uint8_t*) 1022);
}
static void get_pgm_names (vect v) {
  for (uint8_t i = 0; i < v.len / 8; i++)
    eeprom_read_block(v.bytes + 8 * i, (uint8_t*) (i ? eeprom_read_word((uint16_t*) (1022 - 2 * i)) : 0), 8);
}
static void get_pgm_data (vect v) {
  size_t start = 0, end;
  for (uint8_t i = 0; i < v.len / 10; i++) {
    end = eeprom_read_word((uint16_t*) (1020 - 2 * i));
    eeprom_read_block(v.bytes + 10 * i, (uint8_t*) start, 8);
    *((uint16_t*) (v.bytes + 10 * i + 8)) = end - start - 8;
    start = end;
  }
}
static uint8_t get_indexof_pgm (char *name) {
  uint8_t pgm_count = get_pgm_count();
  char n[8];
  for (uint8_t i = 0; i < pgm_count; i++) {
    eeprom_read_block(n, (uint8_t*) (i ? eeprom_read_word((uint16_t*) (1022 - 2 * i)) : 0), 8);
    if (memcmp(n, name, 8) == 0) return i;
  }
  return UINT8_MAX;
}

// 1012 because 10 bytes are guaranteed to be used to hold the address and name of the next program
static uint16_t get_mem () {
  uint8_t pgm_count = get_pgm_count();
  if (pgm_count == 0) return 1012;
  uint16_t last_addr = eeprom_read_word((uint16_t*) (1022 - 2 * pgm_count));
  return 1012 - 2 * pgm_count - last_addr;
}

static struct handle get_next_handle () {
  uint8_t pgm_count = get_pgm_count();
  uint8_t *end = (uint8_t*) (pgm_count == 0 ? 0 : eeprom_read_word((uint16_t *) (1022 - 2 * pgm_count)));
  struct handle h = { .index = pgm_count, .bytes = end }; // len??
  return h;
}

static struct handle get_handle (uint8_t index) {
  uint8_t pgm_count = get_pgm_count();
  if (pgm_count <= index) {
    struct handle null_handle = { .len = 0, .index = pgm_count, .bytes = 0 };
    return null_handle;
  }
  uint8_t *nxptr = (uint8_t*) eeprom_read_word((uint16_t*) (1020 - 2 * index));
  uint8_t *ptr;
  uint16_t len;
  if (index == 0) {
    ptr = 0;
    len = (uint16_t) nxptr;
  } else {
    ptr = (uint8_t*) eeprom_read_word((uint16_t*) (1022 - 2 * index));
    len = (uint16_t) (nxptr - ptr);
  }
  struct handle h = { .index = index, .len = len, .bytes = ptr };
  return h;
}

static void fresh_pgm_name (vect name) { // TODO can improve for space-prefixed names
  uint8_t pgm_count = get_pgm_count();
  uint8_t info[pgm_count * 8];
  vect names = { .len = pgm_count * 8, .bytes = info };
  get_pgm_names(names);
  uint8_t i, k = 0, len;
  do {
    if (k++) decimal(name.bytes, k - 1);
    for (i = 0; i < pgm_count; i++)
      if (memcmp(names.bytes + 8 * i, name.bytes, 8) == 0) break;
  } while (i != pgm_count && k != UINT8_MAX);
}

static struct handle save_file (struct file f) {
  struct handle h = get_next_handle();
  eeprom_update_block(f.name, h.bytes, 8);
  eeprom_update_block(f.bytes, h.bytes + 8, f.len);
  eeprom_update_word((uint16_t*) (1020 - 2 * h.index), (uint16_t) (h.bytes + 8 + f.len));
  eeprom_update_byte((uint8_t*) 1022, h.index + 1);
  return h;
}

static struct file read_file (uint8_t index) {
  struct handle h = get_handle(index);
  if (h.len == 0) {
    struct file null_file = { .len = 0, .name = ((uint64_t*) &h.index), .bytes = 0 };
    return null_file;
  }
  uint8_t bytes[h.len];
  eeprom_read_block(bytes, h.bytes, h.len);
  struct file f = { .bytes = bytes + 8, .len = h.len, .name = (uint64_t*) bytes };
  return f;
};



// Commands

// If the MSB of the last word of EEPROM is 0xDE, treat it as initialised
static vect summary () {
  uint8_t sigbyte = eeprom_read_byte((uint8_t*) 1023);
  int len;
  static uint16_t *bytes;
  if (sigbyte != 0xDE) {
    bytes = malloc(4);
    bytes[0] = 0;
    bytes[1] = 1012;
    len = 4;
    eeprom_update_word((uint16_t*) 1022, 0xDE00);
  } else {
    uint8_t pgm_count = get_pgm_count();
    bytes = malloc(4 + 2 * pgm_count);
    bytes[0] = pgm_count;
    len = 4 + pgm_count * 2;
    for (uint8_t i = 0; i < pgm_count; i++)
      bytes[2 + i] = eeprom_read_word((uint16_t *) (1020 - 2 * i));
    uint16_t mem_used = pgm_count == 0 ? 0 : bytes[1 + pgm_count];
    bytes[1] = 1012 - 2 * pgm_count - mem_used;
  }
  vect data = { .len = len, .bytes = bytes };
  return data;
}

static uint8_t find_pgm () {
  char b_name[8];
  vect v_name = { .len = 8, .bytes = b_name };
  uart_read(v_name);
  uint8_t index = get_indexof_pgm(v_name.bytes);
  if (index == UINT8_MAX) {
    uint8_t pgm_count = get_pgm_count();
    uint8_t info[pgm_count * 8];
    vect v_info = { .len = pgm_count * 8, .bytes = info };
    get_pgm_names(v_info);
    cli();
    uart_put_char(TX_NOTFOUND);
    uart_put_char(pgm_count);
    uart_write(v_info);
    sei();
    state = ST_DONE;
  }
  return index;
}

static uint8_t valid_index (uint8_t cmd) {
  uint8_t index;
  if (cmd & 32) {
    index = find_pgm();
    if (index == UINT8_MAX) return UINT8_MAX;
  } else {
    index = uart_get_char();
    uint8_t count = get_pgm_count();
    if (index >= count) {
      tell_rangeerr(count);
      return UINT8_MAX;
    }
  }
  return index;
}

static struct entry save (uint8_t* nameb) {
  uint16_t len = get_varuint16();
  uint16_t mem = get_mem();
  if (mem < len + 10) {
    uart_skip(len + 8);
    struct entry null_entry = { .len = mem };
    return null_entry;
  }
  vect name = { .len = 8, .bytes = nameb };
  uart_read(name);
  fresh_pgm_name(name);
  uint8_t pgmb[len];
  vect pgm = { .len = len, .bytes = pgmb };
  uart_read(pgm);
  struct file f = { .name = (uint64_t*) nameb, .len = len, .bytes = pgmb };
  struct handle h = save_file(f);
  struct entry entry = { .len = len, .index = h.index, .name = (uint64_t*) nameb };
  return entry;
}

static uint8_t delete (uint8_t index) {
  uint8_t pgm_count = get_pgm_count();
  if (pgm_count <= index) return pgm_count;
  if (pgm_count - 1 > index) {
    struct handle h_next = get_handle(index + 1);
    struct handle h_end = get_next_handle();

    // Shift subseq. EEPROM
    uint16_t len = (uint16_t) (h_end.bytes - h_next.bytes);
    uint8_t eep_block[len];
    eeprom_read_block(eep_block, h_next.bytes, len);
    struct handle h_del = get_handle(index);
    eeprom_update_block(eep_block, h_del.bytes, len);

    // Decrease pointers
    uint8_t del_pgm_cnt = pgm_count - index - 1;
    uint8_t del_len = 2 * del_pgm_cnt;
    uint16_t *pgms = malloc(del_len);
    eeprom_read_block(pgms, (uint8_t*) (1022 - 2 * pgm_count), del_len);
    uint16_t pgm_len = (uint16_t) (h_next.bytes - h_del.bytes);
    for (int i = 0; i < del_pgm_cnt; i++) pgms[i] -= pgm_len;
    eeprom_update_block(pgms, (uint8_t*) (1024 - 2 * pgm_count), del_len);
    free(pgms);
  }
  eeprom_update_byte((uint8_t*) 1022, pgm_count - 1);
  return 0;
}

// static void param () {

// }

static void tell_rangeerr (uint8_t count) {
  cli();
  uart_put_char(TX_RANGEERR);
  uart_put_char(count);
  sei();
  state = ST_DONE;
}

static void tell_ram () {
  uart_put_char(TX_MONITOR);
  put_varuint16(peak_ram);
}

#ifdef DEBUG_NBE
  static void hex (char *ptr, uint8_t n) {
    uint8_t nibble[2] = { n >> 4, n & 0xF };
    ptr[0] = (char) (nibble[0] + (nibble[0] > 9 ? 0x37 : 0x30));
    ptr[1] = (char) (nibble[1] + (nibble[1] > 9 ? 0x37 : 0x30));
  }

  static void imm_debug (vect v, uint8_t ret) {
    uint16_t ram = get_ram();
    uart_put_char(TX_RESULT); // Change?
    uart_put_char(RET_MULTI | ret);
    put_varuint16(v.len + varuint_len(indent) + varuint_len(ram));
    put_varuint16(indent);
    put_varuint16(ram);
    uart_write(v);
  }
#endif



// Runtime structures
static void parse (uint8_t index) {
  struct handle h = get_handle(index);
  if (h.len == 0) return;

  // first pass - locate sections and get top length
  uint8_t *readptr = h.bytes + 11;
  size_t top_size = eeprom_varuint_to_uint16(readptr);
  uint8_t top_size_len = varuint_len(top_size);
  uint8_t *top_ptr = readptr + top_size_len;
  readptr += top_size_len + top_size + 1;

  size_t loc_size = eeprom_varuint_to_uint16(readptr);
  uint8_t loc_size_len = varuint_len(loc_size);
  uint8_t *loc_ptr = readptr + loc_size_len;
  readptr += loc_size_len + loc_size + 1;

  readptr += varuint_len(eeprom_varuint_to_uint16(readptr));

  size_t app_size = eeprom_varuint_to_uint16(readptr);
  uint8_t app_size_len = varuint_len(app_size);
  uint8_t *app_ptr = readptr + app_size_len;
  readptr += app_size_len + app_size;

  size_t lam_size = eeprom_varuint_to_uint16(readptr);
  uint8_t lam_size_len = varuint_len(lam_size);
  uint8_t *lam_ptr = readptr + lam_size_len;
  readptr += lam_size_len + lam_size;

  size_t let_size = eeprom_varuint_to_uint16(readptr);
  uint8_t let_size_len = varuint_len(let_size);
  uint8_t *let_ptr = readptr + let_size_len;
  readptr += let_size_len + let_size + 1;

  size_t defns_size = eeprom_varuint_to_uint16(readptr);
  uint8_t defns_size_len = varuint_len(defns_size);
  uint8_t *defns_ptr = readptr + defns_size_len;
  readptr += defns_size_len + defns_size + 1;

  uint8_t *result_ptr = readptr + 1;

  // second pass - allocations
  array_init(&pgm.loc_names, sizeof(loc));
  array_init(&pgm.apps, sizeof(app));
  array_init(&pgm.lams, sizeof(lam));
  array_init(&pgm.lets, sizeof(let));

  array_init(&pgm.topenv, sizeof(ventry));
  array_init(&pgm.vtops, sizeof(vtop));
  array_init(&pgm.vlocs, sizeof(vloc));
  array_init(&pgm.vlams, sizeof(vlam));

  array_init(&pgm.spines, sizeof(array));
  array_init(&pgm.closures, sizeof(array));

  // top_names
  // assert *(top_ptr - 2) == 0
  // TODO sanitise zero-length strings
  uint8_t top_len = 0;
  if (top_size) {
    uint8_t top_str_init[top_size - 1];
    top top_names[top_size / 2];
    uint8_t *top_str_ptr = top_str_init;
    for (size_t i = 0; i < top_size; top_len++) {
      uint8_t str_len = eeprom_read_byte(top_ptr + i);
      eeprom_read_block(top_str_ptr, top_ptr + i + 1, str_len);
      top_names[top_len] = (top) { .len = str_len, .bytes = top_str_ptr };
      i += 1 + str_len;
      top_str_ptr += str_len;
    }
    uint8_t *top_strings = arena_alloc(top_size - top_len);
    memcpy(top_strings, top_str_init, top_size - top_len);
    pgm.top_names = (vect) {
      .len = top_len * sizeof(top),
      .bytes = arena_alloc(top_len * sizeof(top))
    };
    for (uint8_t i = 0; i < top_len; i++) {
      ((top*) pgm.top_names.bytes)[i] = (top) {
        .len = top_names[i].len,
        .bytes = top_strings
      };
      top_strings += top_names[i].len;
    }
  } else pgm.top_names = (vect) { .len = 0, .bytes = NULL };

  // loc_names
  // assert *(loc_ptr - 2) == 1
  if (loc_size) {
    uint8_t loc_str_init[loc_size - 1];
    loc loc_names[loc_size / 2];
    uint8_t *loc_str_ptr = loc_str_init;
    uint8_t loc_len = 0;
    for (size_t i = 0; i < loc_size; loc_len++) {
      uint8_t str_len = eeprom_read_byte(loc_ptr + i);
      eeprom_read_block(loc_str_ptr, loc_ptr + i + 1, str_len);
      loc_names[loc_len] = (loc) { .len = str_len, .bytes = loc_str_ptr };
      i += 1 + str_len;
      loc_str_ptr += str_len;
    }
    uint8_t *loc_strings = arena_alloc(loc_str_ptr - loc_str_init);
    memcpy(loc_strings, loc_str_init, loc_str_ptr - loc_str_init);
    for (uint8_t i = 0; i < loc_len; i++) {
      *((loc*) array_extend(&pgm.loc_names)) = (loc) {
        .len = loc_names[i].len,
        .bytes = loc_strings
      };
      loc_strings += loc_names[i].len;
    }
  }

  // terms
  // assert *(app_ptr - 3) == 2
  for (size_t i = 0; i < app_size; i += sizeof(app))
    eeprom_read_block(array_extend(&pgm.apps), app_ptr + i, sizeof(app));

  for (size_t i = 0; i < lam_size; i += sizeof(lam))
    eeprom_read_block(array_extend(&pgm.lams), lam_ptr + i, sizeof(lam));

  for (size_t i = 0; i < let_size; i += sizeof(let))
    eeprom_read_block(array_extend(&pgm.lets), let_ptr + i, sizeof(let));
  
  // defns
  // assert *(defns_ptr - 2) == 3, *(defns_ptr - 1) == top_len * 2
  if (top_len) {
    pgm.defns = (vect) {
      .len = top_len * sizeof(term_ref),
      .bytes = arena_alloc(top_len * sizeof(term_ref))
    };
    eeprom_read_block(pgm.defns.bytes, defns_ptr, top_len * sizeof(term_ref));
  } else pgm.defns = (vect) { .len = 0, .bytes = NULL };

  // result
  // assert *(result_ptr - 2) == 4, *(result_ptr - 1) == 2
  eeprom_read_block(&pgm.result, result_ptr, 2);
}

static void parse_immed () {
  get_varuint16(); // pgm_size
  // TODO ram error?

  array_init(&pgm.loc_names, sizeof(loc));
  array_init(&pgm.apps, sizeof(app));
  array_init(&pgm.lams, sizeof(lam));
  array_init(&pgm.lets, sizeof(let));

  array_init(&pgm.topenv, sizeof(ventry));
  array_init(&pgm.vtops, sizeof(vtop));
  array_init(&pgm.vlocs, sizeof(vloc));
  array_init(&pgm.vlams, sizeof(vlam));

  array_init(&pgm.spines, sizeof(array));
  array_init(&pgm.closures, sizeof(array));

  // top_names
  uart_skip(3); // prelude, section=0
  size_t top_size = get_varuint16();
  uint8_t top_len = 0;
  if (top_size) {
    uint8_t top_str_init[top_size - 1];
    top top_names[top_size / 2];
    uint8_t *top_str_ptr = top_str_init;
    for (size_t i = 0; i < top_size; top_len++) {
      uint8_t str_len = uart_get_char();
      top top_term = { .len = str_len, .bytes = top_str_ptr };
      uart_read_short(*((vect_short*) &top_term));
      top_names[top_len] = top_term;
      i += 1 + str_len;
      top_str_ptr += str_len;
    }
    uint8_t *top_strings = arena_alloc(top_size - top_len);
    memcpy(top_strings, top_str_init, top_size - top_len);
    pgm.top_names = (vect) {
      .len = top_len * sizeof(top),
      .bytes = arena_alloc(top_len * sizeof(top))
    };
    for (uint8_t i = 0; i < top_len; i++) {
      ((top*) pgm.top_names.bytes)[i] = (top) {
        .len = top_names[i].len,
        .bytes = top_strings
      };
      top_strings += top_names[i].len;
    }
  } else pgm.top_names = (vect) { .len = 0, .bytes = NULL };

  // loc_names
  uart_skip(1); // section=1
  size_t loc_size = get_varuint16();
  if (loc_size) {
    uint8_t loc_str_init[loc_size - 1];
    loc loc_names[loc_size / 2];
    uint8_t *loc_str_ptr = loc_str_init;
    uint8_t loc_len = 0;
    for (size_t i = 0; i < loc_size; loc_len++) {
      uint8_t str_len = uart_get_char();
      loc loc_term = { .len = str_len, .bytes = loc_str_ptr };
      uart_read_short(*((vect_short*) &loc_term));
      loc_names[loc_len] = loc_term;
      i += 1 + str_len;
      loc_str_ptr += str_len;
    }
    uint8_t *loc_strings = arena_alloc(loc_str_ptr - loc_str_init);
    memcpy(loc_strings, loc_str_init, loc_str_ptr - loc_str_init);
    for (uint8_t i = 0; i < loc_len; i++) {
      *((loc*) array_extend(&pgm.loc_names)) = (loc) {
        .len = loc_names[i].len,
        .bytes = loc_strings
      };
      loc_strings += loc_names[i].len;
    }
  }


  // terms
  uart_skip(1); // section=2
  get_varuint16(); // terms_size
  size_t app_size = get_varuint16();
  for (size_t i = 0; i < app_size; i += sizeof(app))
    uart_read_short((vect_short) { .len = 4, .bytes = array_extend(&pgm.apps) });

  size_t lam_size = get_varuint16();
  for (size_t i = 0; i < lam_size; i += sizeof(lam))
    uart_read_short((vect_short) { .len = 3, .bytes = array_extend(&pgm.lams) });

  size_t let_size = get_varuint16();
  for (size_t i = 0; i < let_size; i += sizeof(let))
    uart_read_short((vect_short) { .len = 5, .bytes = array_extend(&pgm.lets) });

  // defns
  uart_skip(1); // section=3
  get_varuint16(); // defns_size
  if (top_len) {
    pgm.defns = (vect) {
      .len = top_len * sizeof(term_ref),
      .bytes = arena_alloc(top_len * sizeof(term_ref))
    };
    uart_read(pgm.defns);
  } else pgm.defns = (vect) { .len = 0, .bytes = NULL };

  // result
  uart_skip(2); // section=4, len=2
  uart_read_short((vect_short) { .len = 2, .bytes = &pgm.result });
}

static void emit() {
  // first pass - get section and program bytecode sizes
  size_t pgm_len = 2;

  size_t top_size = 0;
  for (uint8_t i = 0; i < pgm.top_names.len / sizeof(top); i++)
    top_size += 1 + ((top*) pgm.top_names.bytes)[i].len;
  pgm_len += 1 + varuint_len(top_size) + top_size;

  size_t loc_size = 0;
  for (uint8_t i = 0; i < pgm.loc_names.len; i++)
    loc_size += 1 + ((loc*) array_access(&pgm.loc_names, i))->len;
  pgm_len += 1 + varuint_len(loc_size) + loc_size;

  size_t terms_size = 0;
  size_t app_size = 4 * pgm.apps.len;
  terms_size += varuint_len(app_size) + app_size;

  size_t lam_size = 3 * pgm.lams.len;
  terms_size += varuint_len(lam_size) + lam_size;

  size_t let_size = 5 * pgm.lets.len;
  terms_size += varuint_len(let_size) + let_size;

  pgm_len += 1 + varuint_len(terms_size) + terms_size;

  size_t defns_size = pgm.defns.len;
  pgm_len += 2 + defns_size;

  pgm_len += 4;

  // second pass - put bytes
  put_varuint16(pgm_len);
  uart_put_char(0xDE);
  uart_put_char(0xC0);

  // top_names
  uart_put_char(0x00);
  put_varuint16(top_size);
  for (size_t i = 0; i < pgm.top_names.len; i += sizeof(top)) {
    top *str = (top*) (pgm.top_names.bytes + i); // Was this correct?
    uart_put_char(str->len);
    uart_write((vect) { .len = str->len, .bytes = str->bytes });
  }

  // loc_names
  uart_put_char(0x01);
  put_varuint16(loc_size);
  for (uint8_t i = 0; i < pgm.loc_names.len; i++) {
    loc* str = (loc*) array_access(&pgm.loc_names, i);
    uart_put_char(str->len);
    uart_write((vect) { .len = str->len, .bytes = str->bytes });
  }

  // terms
  uart_put_char(0x02);
  put_varuint16(terms_size);

  put_varuint16(app_size);
  for (uint8_t i = 0; i < pgm.apps.len; i++) {
    app *app_term = array_access(&pgm.apps, i);
    uart_write((vect) { .len = 4, .bytes = app_term });
  }

  put_varuint16(lam_size);
  for (uint8_t i = 0; i < pgm.lams.len; i++) {
    lam *lam_term = array_access(&pgm.lams, i);
    uart_write((vect) { .len = 3, .bytes = lam_term });
  }

  put_varuint16(let_size);
  for (uint8_t i = 0; i < pgm.lets.len; i++) {
    let *let_term = array_access(&pgm.lets, i);
    uart_write((vect) { .len = 5, .bytes = let_term });
  }

  // defns
  uart_put_char(0x03);
  put_varuint16(defns_size);
  uart_write(pgm.defns);


  // result
  uart_put_char(0x04);
  uart_put_char(0x02);
  uart_put_char(pgm.result.id);
  uart_put_char(pgm.result.ix);

  arena_free(); // End of computation
}



// NbE
// name: top or loc as vect_short
static val_ref lookup (vect_short *name, array *env) {
#ifdef DEBUG_NBE
  imm_debug((vect) { .len = 6, .bytes = qs.lookup + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  val_ref result = { .id = 3 }; // "NULL"
  for (uint8_t i = 0; i < env->len; i++) {
    ventry *ve = array_access(env, i);
    vect_short *el = (vect_short*) ve->name;
    if (name->len != el->len) continue;
    if (memcmp(name->bytes, el->bytes, name->len) != 0) continue;
    result = ve->value;
    break;
  }
#ifdef DEBUG_NBE
  indent--;
  imm_debug((vect) { .len = 7, .bytes = qs.lookup }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static val_ref eval (term_ref tm, array *env) {
#ifdef DEBUG_NBE
  memcpy(qs.eval + 6, tids + tm.id * 3, 3);
  hex(qs.eval + 10, (uint8_t) tm.ix);
  imm_debug((vect) { .len = 11, .bytes = qs.eval + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  vect_short *name;
  val_ref result;
  switch (tm.id) {
    case TOP:
    name = (vect_short*) pgm.top_names.bytes + tm.ix;
    val_ref found = lookup(name, &pgm.topenv);
    if (found.id == 3) {
      result = found; // Error...
      break;
    }
    array_init(array_extend(&pgm.spines), sizeof(val_ref));
    *((vtop*) array_extend(&pgm.vtops)) = (vtop) { .index = tm.ix, .value = found, .sp_ix = pgm.spines.len - 1 };
    result = (val_ref) { .id = VTOP, .ix = pgm.vtops.len - 1 };
    break;

    case LOC:
    result = lookup(array_access(&pgm.loc_names, tm.ix), env);
    break;
    
    case APP: nop;
    app *app_term = array_access(&pgm.apps, tm.ix);
    val_ref vfunc = eval(app_term->func, env);
    val_ref varg = eval(app_term->arg, env);
    result = vapp(vfunc, varg);
    break;

    case LAM: nop;
    lam *lam_term = array_access(&pgm.lams, tm.ix);
    name = (vect_short*) array_access(&pgm.loc_names, lam_term->index);
    array_copy(array_init(array_extend(&pgm.closures), sizeof(ventry)), env);
    *((vlam*) array_extend(&pgm.vlams)) = (vlam) { .binder = name, .body = lam_term->body, .cl_ix = pgm.closures.len - 1 };
    result = (val_ref) { .id = VLAM, .ix = pgm.vlams.len - 1 };
    break;

    case LET: nop;
    let *let_term = array_access(&pgm.lets, tm.ix);
    name = (vect_short*) array_access(&pgm.loc_names, let_term->index);
    *((ventry*) array_extend(env)) = (ventry) { .name = name, .value = eval(let_term->term, env) };
    result = eval(let_term->result, env);
    array_shrink(env);
    break;

    default: result = (val_ref) { .id = 3 }; // TODO how to errors
  }
#ifdef DEBUG_NBE
  indent--;
  memcpy(qs.eval + 6, tids + tm.id * 3, 3);
  hex(qs.eval + 10, (uint8_t) tm.ix);
  imm_debug((vect) { .len = 12, .bytes = qs.eval }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static val_ref capp (vlam *vfunc, val_ref varg) {
#ifdef DEBUG_NBE
  imm_debug((vect) { .len = 4, .bytes = qs.capp + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  array *cls = array_access(&pgm.closures, vfunc->cl_ix);
  *((ventry*) array_extend(cls)) = (ventry) { .name = vfunc->binder, .value = varg };
  val_ref result = eval(vfunc->body, cls);
  array_shrink(cls);
#ifdef DEBUG_NBE
  indent--;
  imm_debug((vect) { .len = 5, .bytes = qs.capp }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static val_ref vapp (val_ref vfunc, val_ref varg) {
#ifdef DEBUG_NBE
  memcpy(qs.vapp + 6, vids + vfunc.id * 4, 4);
  memcpy(qs.vapp + 11, vids + varg.id * 4, 4);
  imm_debug((vect) { .len = 14, .bytes = qs.vapp + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  val_ref result;
  switch (vfunc.id) {
    case VTOP: nop;
    vtop *vt = array_access(&pgm.vtops, vfunc.ix);
    *((val_ref*) array_extend(array_copy(
      array_init(array_extend(&pgm.spines), sizeof(val_ref)),
      array_access(&pgm.spines, vt->sp_ix)
    ))) = varg;
    val_ref val = vapp(vt->value, varg);
    *((vtop*) array_extend(&pgm.vtops)) = (vtop) { .index = vt->index, .value = val, .sp_ix = pgm.spines.len - 1 };
    result = (val_ref) { .id = VTOP, .ix = pgm.vtops.len - 1 };
    break;

    case VLOC: nop;
    vloc *vl = array_access(&pgm.vlocs, vfunc.ix);
    *((val_ref*) array_extend(array_copy(
      array_init(array_extend(&pgm.spines), sizeof(val_ref)),
      array_access(&pgm.spines, vl->sp_ix)
    ))) = varg;
    *((vloc*) array_extend(&pgm.vlocs)) = (vloc) { .name = vl->name, .sp_ix = pgm.spines.len - 1 };
    result = (val_ref) { .id = VLOC, .ix = pgm.vlocs.len - 1 };
    break;

    case VLAM:
    result = capp(array_access(&pgm.vlams, vfunc.ix), varg);
    break;

    default: result = (val_ref) { .id = 3 };
  }
#ifdef DEBUG_NBE
  indent--;
  memcpy(qs.vapp + 6, vids + vfunc.id * 4, 4);
  memcpy(qs.vapp + 11, vids + varg.id * 4, 4);
  imm_debug((vect) { .len = 15, .bytes = qs.vapp }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static vect_short *fresh (vect_short *name, array *env) {
#ifdef DEBUG_NBE
  imm_debug((vect) { .len = 5, .bytes = qs.fresh + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  val_ref found_old = lookup(name, env);
  vect_short *result = NULL;
  if (found_old.id == 3) result = name;
  else {
    char new_string[name->len + 1];
    memcpy(new_string, name->bytes, name->len);
    new_string[name->len] = '\'';
    vect_short new_name = { .len = name->len + 1, .bytes = new_string };
    uint8_t index_new = array_indexof(&pgm.loc_names, &new_name);
    if (index_new == UINT8_MAX) {
      *((vect_short*) array_extend(&pgm.loc_names)) = new_name;
      index_new = name->len;
    }
    result = array_access(&pgm.loc_names, index_new);
  }
#ifdef DEBUG_NBE
  indent--;
  imm_debug((vect) { .len = 6, .bytes = qs.fresh }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static term_ref quote (val_ref val, array *env) {
#ifdef DEBUG_NBE
  memcpy(qs.quote + 7, vids + val.id * 4, 4);
  imm_debug((vect) { .len = 10, .bytes = qs.quote + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();

  term_ref result;
  switch (val.id) {
    case VTOP: nop;
    vtop *vt = array_access(&pgm.vtops, val.ix);
    result = pgm.unfoldtop ?
      quote(vt->value, env) :
      quote_sp(
        (term_ref) { .id = TOP, .ix = vt->index },
        array_access(&pgm.spines, vt->sp_ix),
        env
      );
    break;

    case VLOC: nop;
    vloc *vl = array_access(&pgm.vlocs, val.ix);
    uint8_t index = array_indexof(&pgm.loc_names, vl->name);
    term_ref ref = { .id = LOC, .ix = index };
    result = quote_sp(ref, array_access(&pgm.spines, vl->sp_ix), env);
    break;

    case VLAM: nop;
    vlam *vm = array_access(&pgm.vlams, val.ix);
    vect_short *nn = fresh(vm->binder, env);
    array_init(array_extend(&pgm.spines), sizeof(val_ref));
    *((vloc*) array_extend(&pgm.vlocs)) = (vloc) { .name = nn, .sp_ix = pgm.spines.len - 1 };
    val_ref nv = { .id = VLOC, .ix = pgm.vlocs.len - 1 };
    *((ventry*) array_extend(env)) = (ventry) { .name = nn, .value = nv };
    term_ref new_body = quote(capp(vm, nv), env);
    array_shrink(env);
    *((lam*) array_extend(&pgm.lams)) = (lam) { .index = array_indexof(&pgm.loc_names, nn), .body = new_body };
    result = (term_ref) { .id = LAM, .ix = pgm.lams.len - 1 };
    break;

    default: result = (term_ref) { .id = 5 }; // No :(
  }
#ifdef DEBUG_NBE
  indent--;
  memcpy(qs.quote + 7, vids + val.id * 4, 4);
  imm_debug((vect) { .len = 11, .bytes = qs.quote }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static term_ref quote_sp (term_ref tm, array *sp, array *env) {
#ifdef DEBUG_NBE
  imm_debug((vect) { .len = 8, .bytes = qs.quote_sp + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  term_ref result = tm;
  for (uint8_t i = 0; i < sp->len; i++) {
    term_ref arg = quote(*((val_ref*) array_access(sp, i)), env);
    *((app*) array_extend(&pgm.apps)) = (app) { .func = result, .arg = arg };
    result = (term_ref) { .id = APP, .ix = pgm.apps.len - 1 };
  }
#ifdef DEBUG_NBE
  indent--;
  imm_debug((vect) { .len = 9, .bytes = qs.quote_sp }, RET_STRING);
#endif
  set_peak_ram();
  return result;
}

static void nf_top () { // When do we want to keep the pre-term?
#ifdef DEBUG_NBE
  imm_debug((vect) { .len = 6, .bytes = qs.nf_top + 1 }, RET_STRING);
  indent++;
#endif
  set_peak_ram();
  for (uint8_t i = 0; i < pgm.defns.len / sizeof(term_ref); i++) {
    *((ventry*) array_extend(&pgm.topenv)) = (ventry) {
      .name = (vect_short*) pgm.top_names.bytes + i,
      .value = eval(((term_ref*) pgm.defns.bytes)[i], &pgm.topenv) };
  }
  val_ref final_val = eval(pgm.result, &pgm.topenv);
  array *locenv = array_init(arena_alloc(sizeof(array)), sizeof(ventry));
  pgm.result = quote(final_val, locenv);
  set_peak_ram();
#ifdef DEBUG_NBE
  indent--;
  imm_debug((vect) { .len = 7, .bytes = qs.nf_top }, RET_STRING);
#endif
}
