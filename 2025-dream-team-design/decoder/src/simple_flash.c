/**
 * @file simple_flash.c
 * @author Dream Team
 * @brief Simple Flash Interface Implementation 
 * @date 2025
 *
 */

#include "simple_flash.h"

#include <stdio.h>
#include "flc.h"
#include "icc.h"
#include "nvic_table.h"

/**
 * @brief ISR for the Flash Controller
 * 
 * This ISR allows for access to the flash through simple_flash to operate
 */
void flash_simple_irq(void) {
    uint32_t temp = MXC_FLC0->intr;

    if (temp & MXC_F_FLC_INTR_DONE) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_DONE;
    }

    if (temp & MXC_F_FLC_INTR_AF) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_AF;
        printf(" -> Interrupt! (Flash access failure)\n\n");
    }
}

/**
 * @brief Initialize the Simple Flash Interface
 * 
 * This function registers the interrupt for the flash system,
 * enables the interrupt, and disables ICC
 */
void flash_simple_init(void) {
    // Setup Flash
    MXC_NVIC_SetVector(FLC0_IRQn, flash_simple_irq);
    NVIC_EnableIRQ(FLC0_IRQn);
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
    MXC_ICC_Disable(MXC_ICC0);
}

/**
 * @brief Flash Simple Erase Page
 * 
 * @param address: uint32_t, address of flash page to erase
 * 
 * @return int: return negative if failure, zero if success
 * 
 * This function erases a page of flash such that it can be updated.
 */
int flash_simple_erase_page(uint32_t address) {
    return MXC_FLC_PageErase(address);
}

/**
 * @brief Flash Simple Read
 * 
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 * 
 * This function reads data from the specified flash page into the buffer.
 */
void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    if (buffer == NULL || size == 0) {
        return;
    }
    MXC_FLC_Read(address, (uint32_t *)buffer, size);
}

/**
 * @brief Flash Simple Write
 * 
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed.
 */
int flash_simple_write(uint32_t address, const void* buffer, uint32_t size) {
    if (buffer == NULL || size == 0) {
        return -1;
    }
    return MXC_FLC_Write(address, size, (const uint32_t *)buffer);
}
