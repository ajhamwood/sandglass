.global main



;; Initialise
main:

;; DDRC = 0xFF (Enable PORTC)
LDI r16, 0xFF
OUT 0x07, r16
CLR r16
OUT 0x08, r16



;; Serial communication
;; Disable global interrupts
CLI

;; BAUD = 38400, 8MHz clock => UBRR0 <- 12
LDI r16, 0x0C
STS 0xC4, r16
CLR r16
STS 0xC5, r16

;; UCSR0B = 0b00011000
;; (Enable receive, transmit)
LDI r16, 0x18
STS 0xC1, r16

;; UCSR0C = 0b00000110
;; (Asynchronous mode, no parity bit
;;  Frame format: 8 bits data + 1 stop bit)
LDI r16, 0x06
STS 0xC2, r16

;; Enable global interrupts
SEI



;; EEPROM
;; Write only programming mode
SBI 0x1F, 5



;; Await request from sandglass.py
wait_USART0_RX_request:
CLR r22

LDS r16, 0xC0
SBRS r16, 7
RJMP wait_USART0_RX_request

LDS r16, 0xC6
LDI r17, 0x03
CP r16, r17
BRLT upload_request
CP r16, r17
BREQ load_eeprom_request
RJMP wait_USART0_RX_request
RJMP bad_request



;; Check EEPROM for signature
load_eeprom_request:
CLR r27
CLR r26
LDI r17, 0x04

EEPROM_read:
SBIC 0x1F, 1
RJMP EEPROM_read

STS 0x42, r27
STS 0x41, r26

SBI 0x1F, 0
LDS r16, 0x40
INC r27
ST X+, r16
DEC r27

SEZ
CPSE r27, r17
CP r16, r17
BRNE EEPROM_read

RCALL send_file

RJMP end



;; Await upload
upload_request:
SBRS r16, 0
LDI r22, 0x01  ;; EEPROM save request

wait_USART0_TX_awaiting_bytes:
LDS r16, 0xC0
SBRS r16, 5
RJMP wait_USART0_TX_awaiting_bytes

LDI r16, 0x01  ;; awaiting-bytes signal
STS 0xC6, r16

LDI r27, 0x01
CLR r26
LDI r25, 0x05
CLR r24



;; Receive file
wait_USART0_RX_file:
LDS r16, 0xC0
SBRS r16, 7
RJMP wait_USART0_RX_file

LDS r16, 0xC6

;; end-of-transmission signal?
LDI r17, 0x04
CP r16, r17
BREQ load_SRAM_complete

;; file size over 1k?
CP r26, r24
CPC r27, r25
BREQ too_big

; Write to SRAM
ST X+, r16

RJMP wait_USART0_RX_file



;; Load into SRAM complete
load_SRAM_complete:
ST X+, r17

LDI r16, 0x01  ;; Is this a save request?
CP r16, r22
BRNE wait_USART0_TX_upload_complete

LDI r27, 0x01
CLR r26
LDI r17, 0x04

;; Write to EEPROM
EEPROM_write:
SBIC 0x1F, 1
RJMP EEPROM_write

DEC r27
STS 0x42, r27
INC r27
STS 0x41, r26
LD r16, X+
STS 0x40, r16

SBI 0x1F, 2
SBI 0x1F, 1

SEZ
CPSE r27, r17
CP r16, r17
BRNE EEPROM_write



;; Upload complete
wait_USART0_TX_upload_complete:
LDS r16, 0xC0
SBRS r16, 5
RJMP wait_USART0_TX_upload_complete

LDI r16, 0x02  ;; upload-complete signal
STS 0xC6, r16

RCALL send_file

RJMP end



;; File too large
too_big:
wait_USART0_TX_file_too_big:
LDS r16, 0xC0
SBRS r16, 5
RJMP wait_USART0_TX_file_too_big

LDI r16, 0x03  ;; file-too-big signal
STS 0xC6, r16

RJMP end



send_file:
LDI r27, 0x01
CLR r26
LDI r17, 0x04

wait_USART0_TX_send_file:
LDS r16, 0xC0
SBRS r16, 5
RJMP wait_USART0_TX_send_file

LD r16, X+
STS 0xC6, r16

CPSE r16, r17
RJMP wait_USART0_TX_send_file
RET



bad_request:
wait_USART0_TX_bad_request:
LDS r16, 0xC0
SBRS r16, 5
RJMP wait_USART0_TX_bad_request

LDI r16, 0x06  ;; bad-request signal
STS 0xC6, r16


end:
RJMP wait_USART0_RX_request
; RJMP end
