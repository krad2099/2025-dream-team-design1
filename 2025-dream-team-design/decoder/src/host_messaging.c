/**
 * @file host_messaging.c
 * @author Dream Team
 * @brief eCTF Host Messaging Implementation 
 * @date 2025
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "host_messaging.h"

/** @brief Read len bytes from UART, acknowledging after every 256 bytes. */
int read_bytes(void *buf, uint16_t len) {
    int result;
    for (uint16_t i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {
            write_ack();
        }
        result = uart_readbyte();
        if (result < 0) {
            return result;
        }
        ((uint8_t *)buf)[i] = (uint8_t)result;
    }
    return 0;
}

/** @brief Read a message header from UART. */
void read_header(msg_header_t *hdr) {
    do {
        hdr->magic = uart_readbyte();
    } while (hdr->magic != MSG_MAGIC);
    hdr->cmd = uart_readbyte();
    read_bytes(&hdr->len, sizeof(hdr->len));
}

/** @brief Receive an ACK from UART. */
uint8_t read_ack() {
    msg_header_t ack_buf = {0};
    read_header(&ack_buf);
    return (ack_buf.cmd == ACK_MSG) ? 0 : (uint8_t)-1;
}

/** @brief Write bytes to console UART. */
int write_bytes(const void *buf, uint16_t len, bool should_ack) {
    for (uint16_t i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {
            if (should_ack && read_ack() < 0) {
                return -1;
            }
        }
        uart_writebyte(((const uint8_t *)buf)[i]);
    }
    return 0;
}

/** @brief Write bytes to UART in hex format. */
int write_hex(msg_type_t type, const void *buf, size_t len) {
    msg_header_t hdr = {MSG_MAGIC, type, len * 2};
    write_bytes(&hdr, MSG_HEADER_SIZE, false);
    if (type != DEBUG_MSG && read_ack() < 0) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        if (i % 128 == 0 && i != 0) {
            if (type != DEBUG_MSG && read_ack() < 0) {
                return -1;
            }
        }
        printf("%02x", ((const uint8_t *)buf)[i]);
        fflush(stdout);
    }
    return 0;
}

/** @brief Send a message to the host with acknowledgment checks. */
int write_packet(msg_type_t type, const void *buf, uint16_t len) {
    msg_header_t hdr = {MSG_MAGIC, type, len};
    if (write_bytes(&hdr, MSG_HEADER_SIZE, false) < 0) {
        return -1;
    }
    if (type == ACK_MSG) {
        return 0;
    }
    if (type != DEBUG_MSG && read_ack() < 0) {
        return -1;
    }
    if (len > 0) {
        if (write_bytes(buf, len, type != DEBUG_MSG) < 0) {
            return -1;
        }
        if (type != DEBUG_MSG && read_ack() < 0) {
            return -1;
        }
    }
    return 0;
}

/** @brief Read a packet from UART. */
int read_packet(msg_type_t *cmd, void *buf, uint16_t *len) {
    if (!cmd) {
        return -1;
    }
    msg_header_t header = {0};
    read_header(&header);
    *cmd = header.cmd;
    if (len) {
        *len = header.len;
    }
    if (header.cmd != ACK_MSG) {
        write_ack();
        if (header.len && buf) {
            if (read_bytes(buf, header.len) < 0) {
                return -1;
            }
        }
        if (header.len) {
            if (write_ack() < 0) {
                return -1;
            }
        }
    }
    return 0;
}
