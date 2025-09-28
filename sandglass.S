.include "m324adef.inc"

.global main

#define temp r24
#define temp2 r25
#define zero r28      // Until I use Y reg
#define zero2 r29
#define high r23
#define count r16
main:
; Start
CLR   zero
CLR   zero2
OUT   SREG,   zero
LDI   high,   0xFF
LDI   temp,   0x08
OUT   SPH,    temp
OUT   SPL,    high
; Remember: never RET or default out of main, no interrupts


; Port C -> LEDs
OUT   DDRC,   high


; Autobaud
LDI   ZL,     0xC0
LDI   ZH,     0x00    ; UCSR0A
LDI   XL,     0x60
LDI   XH,     0xFF    ; -0xA0
LDI   temp,   0xA0

wait_for_rx_low:
SBIC  PIND,   PIND0   ; If RXD0 is high
RJMP wait_for_rx_low

wait_for_rx_high:
ADD   XL,     temp
ADC   XH,     zero
SBIS  PIND,   PIND0
RJMP  wait_for_rx_high
STD   Z+4,    XH      ; UBRR0L


; Set up UART
busy_wait:
SBIW  X,      0x05
BRPL  busy_wait

LDI   XH,     (1 << U2X0)
ST    Z,      XH      ; UCSR0A
LDI   XH,     (1 << RXEN0) | (1 << TXEN0)
STD   Z+1,    XH      ; UCSR0B



loop:
LDI   temp2,   0x02   ; get CLI data signal
RCALL waitch


; Receive null-delimited string and store in program memory
LDI   XL,     0x00
LDI   XH,     0x01    ; Start of SRAM
MOVW  Z,      Y       ; Start of flash
LDI   temp2,  0x80

CLR   count
page_load:
RCALL getch
INC   count
ST    X+,     temp
TST   temp
BREQ  last_write
CPI   XL,     0x80
BRNE  page_load
RCALL write_page
ADIW  Z,      0x02
CLR   XL
RJMP  page_load

last_write:
ST    X+,     high
CPI   XL,     0x80
BRNE  last_write
RCALL write_page


OUT   PORTC,  count
wait_for_request:
LDI   temp,   0x01    ; put CLI ready signal
RCALL putch
LDI   temp2,  0x01    ; get CLI ready signal
RCALL waitch


echo_back:
LDI   temp,   0x02    ; put CLI data signal
RCALL putch

MOVW  Z,      Y       ; Start of flash
loadstr:
LPM   temp,   Z+      ; Get next char and send
RCALL putch
CPSE  temp,   zero    ; Null termination
RJMP  loadstr

RJMP  loop            ; Forever



; Input: char temp2
waitch:
RCALL getch
CPSE  temp,   temp2
RJMP waitch
RET



; Input: char temp
getch:
LDS   temp,   UCSR0A
SBRS  temp,   RXC0    ; Loop until unread data in rx buf
RJMP  getch

LDS   temp,   UDR0
RET



; Output: char temp
putch:
LDS   temp2,  UCSR0A
SBRS  temp2,  UDRE0   ; Data register empty
RJMP  putch

STS   UDR0,   temp
RET



write_page:
CLR   XL
CPI   ZH,     0x70    ; Boot start (edit as appropriate)
BRSH  err

write_page_to_pgm:
LDI   temp,   0x03    ; Perform page erase (*ZH)
RCALL write_pgm
LDI   temp,   0x01    ; Store *X in page buffer (*ZH)

load_for_write:
LD    r0,     X+
LD    r1,     X+
RCALL write_pgm
ADIW  Z,      0x02
CPSE  XL,     temp2
RJMP  load_for_write
SBIW  Z,      0x02
OUT   PORTC,  ZH
LDI   temp,   0x05    ; Write page buffer to PGM
RCALL write_pgm

LDI   temp,   0x11    ; Enable read for read-while-write section
                      ; Then return from write_page
write_pgm:
OUT   SPMCSR, temp
SPM

wait_for_pgm_write:
IN    r1,     SPMCSR
SBRC  r1,     SPMEN   ; While SPMEN set
RJMP  wait_for_pgm_write
EOR   r1,     r1
RET



err:
LDI   temp,   0xFF    ; put CLI error signal
RCALL putch
end:
RJMP  end