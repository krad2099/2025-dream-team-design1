/**
 * @file simple_uart.c
 * @author Dream Team
 * @brief UART Interrupt Handler Implementation 
 * @date 2025
 *
 */

#include "simple_uart.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "uart.h"
#include "nvic_table.h"
#include "host_messaging.h"
#include "board.h"
#include "mxc_device.h"

/** @brief Initializes the UART Interrupt handler.
 * 
 *  @note This function should be called once upon startup.
 *  @return 0 upon success, negative on error.
 */
int uart_init(void) {
    int ret = MXC_UART_Init(MXC_UART_GET_UART(CONSOLE_UART), UART_BAUD, MXC_UART_IBRO_CLK);
    if (ret != E_NO_ERROR) {
        printf("Error initializing UART: %d\n", ret);
        return ret;
    }
    return E_NO_ERROR;
}

/** @brief Reads a byte from UART and reports an error if the read fails.
 * 
 *  @return The character read, or an error code if the read fails.
 */
int uart_readbyte_raw(void) {
    return MXC_UART_ReadCharacterRaw(MXC_UART_GET_UART(CONSOLE_UART));
}

/** @brief Reads the next available character from UART.
 * 
 *  @return The character read, or an error code if the read fails.
 */
int uart_readbyte(void) {
    return MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));
}

/** @brief Writes a byte to UART.
 * 
 *  @param data The byte to be written.
 */
void uart_writebyte(uint8_t data) {
    while (MXC_UART_GET_UART(CONSOLE_UART)->status & MXC_F_UART_STATUS_TX_FULL) {
        // Wait until TX buffer is not full
    }
    MXC_UART_GET_UART(CONSOLE_UART)->fifo = data;
}

/** @brief Flushes UART RX and TX FIFOs.
 */
void uart_flush(void) {
    MXC_UART_ClearRXFIFO(MXC_UART_GET_UART(CONSOLE_UART));
    MXC_UART_ClearTXFIFO(MXC_UART_GET_UART(CONSOLE_UART));
}
