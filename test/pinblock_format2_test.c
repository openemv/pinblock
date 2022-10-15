/**
 * @file pinblock_format2_test.c
 *
 * Copyright (c) 2022 Leon Lynch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "pinblock.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Example from Thales payShield Host Programmer's Manual v1.2a (page 234)
static const uint8_t pin[] = { 0x03, 0x04, 0x05, 0x06, 0x07 };
static const uint8_t pinblock_verify[] = { 0x25, 0x34, 0x56, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF };

static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

int main(void)
{
	int r;
	uint8_t pinblock[PINBLOCK_SIZE];
	unsigned int format;
	uint8_t decoded_pin[12];
	size_t decoded_pin_len = 0;

	// Test ISO 9564-1:2017 PIN block format 2 encoding
	r = pinblock_encode_iso9564_format2(
		pin,
		sizeof(pin),
		pinblock
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format2() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinblock, pinblock_verify, sizeof(pinblock_verify)) != 0) {
		fprintf(stderr, "PIN block is incorrect\n");
		print_buf("pinblock", pinblock, sizeof(pinblock));
		print_buf("pinblock_verify", pinblock_verify, sizeof(pinblock_verify));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 2 decoding
	r = pinblock_decode_iso9564_format2(
		pinblock,
		sizeof(pinblock),
		decoded_pin,
		&decoded_pin_len
	);
	if (r) {
		fprintf(stderr, "pinblock_decode_iso9564_format2() failed; r=%d\n", r);
		goto exit;
	}
	if (decoded_pin_len != sizeof(pin)) {
		fprintf(stderr, "Decoded PIN length is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(decoded_pin, pin, sizeof(pin)) != 0) {
		fprintf(stderr, "Decoded PIN is incorrect\n");
		print_buf("decoded_pin", decoded_pin, sizeof(decoded_pin));
		print_buf("pin", pin, sizeof(pin));
		r = 1;
		goto exit;
	}

	// Test format retrieval
	r = pinblock_get_format(pinblock, sizeof(pinblock));
	if (r < 0) {
		fprintf(stderr, "pinblock_get_format() failed; r=%d\n", r);
		goto exit;
	}
	if (r != PINBLOCK_ISO9564_FORMAT_2) {
		fprintf(stderr, "Failed to retrieve PIN block format; r=%d\n", r);
		r = 1;
		goto exit;
	}

	// Test generic decoding
	r = pinblock_decode(
		pinblock,
		sizeof(pinblock),
		NULL,
		0,
		&format,
		decoded_pin,
		&decoded_pin_len
	);
	if (r) {
		fprintf(stderr, "pinblock_decode() failed; r=%d\n", r);
		goto exit;
	}
	if (format != PINBLOCK_ISO9564_FORMAT_2) {
		fprintf(stderr, "Decoded PIN block format is incorrect\n");
		r = 1;
		goto exit;
	}
	if (decoded_pin_len != sizeof(pin)) {
		fprintf(stderr, "Decoded PIN length is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(decoded_pin, pin, sizeof(pin)) != 0) {
		fprintf(stderr, "Decoded PIN is incorrect\n");
		print_buf("decoded_pin", decoded_pin, sizeof(decoded_pin));
		print_buf("pin", pin, sizeof(pin));
		r = 1;
		goto exit;
	}

	// Test padding validation
	pinblock[6] ^= 1;
	r = pinblock_decode_iso9564_format2(
		pinblock,
		sizeof(pinblock),
		decoded_pin,
		&decoded_pin_len
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_decode_iso9564_format2() unexpectedly succeeded with bad PIN block\n");
		r = 1;
		goto exit;
	}
	if (decoded_pin_len != 0) {
		fprintf(stderr, "Decoded PIN length is incorrect\n");
		r = 1;
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
