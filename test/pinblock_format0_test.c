/**
 * @file pinblock_format0_test.c
 *
 * Copyright 2022, 2025 Leon Lynch
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

// PIN with invalid digit
static const uint8_t pin_invalid[] = { 0x01, 0x02, 0x0A, 0x04 };

// ANSI X9.24-1:2009 A.4 DUKPT Test Data Examples
static const uint8_t pin[] = { 0x01, 0x02, 0x03, 0x04 };
static const uint8_t pan[] = { 0x40, 0x12, 0x34, 0x56, 0x78, 0x90, 0x9F };
static const uint8_t pinblock_verify[] = { 0x04, 0x12, 0x74, 0xED, 0xCB, 0xA9, 0x87, 0x6F };

// Incorrect test PAN
static const uint8_t bad_pan[] = { 0x40, 0x22, 0x34, 0x56, 0x78, 0x90, 0x9F };

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

	printf("Test 1: PIN block encoding with invalid digit...\n");
	r = pinblock_encode_iso9564_format0(
		pin_invalid,
		sizeof(pin_invalid),
		pan,
		sizeof(pan),
		pinblock
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format0() unexpectedly succeeded for invalid PIN\n");
		r = 1;
		goto exit;
	}

	printf("Test 2: PIN block encoding of valid PIN...\n");
	r = pinblock_encode_iso9564_format0(
		pin,
		sizeof(pin),
		pan,
		sizeof(pan),
		pinblock
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format0() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinblock, pinblock_verify, sizeof(pinblock_verify)) != 0) {
		fprintf(stderr, "PIN block is incorrect\n");
		print_buf("pinblock", pinblock, sizeof(pinblock));
		print_buf("pinblock_verify", pinblock_verify, sizeof(pinblock_verify));
		r = 1;
		goto exit;
	}

	printf("Test 3: PIN block format 0 decoding...\n");
	r = pinblock_decode_iso9564_format0(
		pinblock_verify,
		sizeof(pinblock_verify),
		pan,
		sizeof(pan),
		decoded_pin,
		&decoded_pin_len
	);
	if (r) {
		fprintf(stderr, "pinblock_decode_iso9564_format0() failed; r=%d\n", r);
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

	printf("Test 4: PIN block format retrieval...\n");
	r = pinblock_get_format(pinblock_verify, sizeof(pinblock_verify));
	if (r < 0) {
		fprintf(stderr, "pinblock_get_format() failed; r=%d\n", r);
		goto exit;
	}
	if (r != PINBLOCK_ISO9564_FORMAT_0) {
		fprintf(stderr, "Failed to retrieve PIN block format; r=%d\n", r);
		r = 1;
		goto exit;
	}

	printf("Test 5: Generic PIN block decoding...\n");
	r = pinblock_decode(
		pinblock_verify,
		sizeof(pinblock_verify),
		pan,
		sizeof(pan),
		&format,
		decoded_pin,
		&decoded_pin_len
	);
	if (r) {
		fprintf(stderr, "pinblock_decode() failed; r=%d\n", r);
		goto exit;
	}
	if (format != PINBLOCK_ISO9564_FORMAT_0) {
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

	printf("Test 6: Padding validation with incorrect PAN...\n");
	r = pinblock_decode_iso9564_format0(
		pinblock_verify,
		sizeof(pinblock_verify),
		bad_pan,
		sizeof(bad_pan),
		decoded_pin,
		&decoded_pin_len
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_decode_iso9564_format0() unexpectedly succeeded with bad PAN\n");
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
