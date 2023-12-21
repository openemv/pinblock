/**
 * @file pinblock_format4_test.c
 *
 * Copyright 2022 Leon Lynch
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

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (Calculation of AES PIN Block Format 4; top of page 31)
static const uint8_t pin[] = { 0x01, 0x02, 0x03, 0x04 };
static const uint8_t pinfield_verify[] = { 0x44, 0x12, 0x34, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
static const uint8_t pan[] = { 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t panfield_verify[] = { 0x44, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Hand made example
static const uint8_t pin2[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
static const uint8_t pinfield_verify2[] = { 0x45, 0x12, 0x34, 0x5A, 0xAA, 0xAA, 0xAA, 0xAA };
static const uint8_t pan2[] = { 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1F };
static const uint8_t panfield_verify2[] = { 0x34, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Hand made example
static const uint8_t pan3[] = { 0x12, 0x34, 0x56, 0x78, 0x9F };
static const uint8_t panfield_verify3[] = { 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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
	uint8_t pinfield[PINBLOCK128_SIZE];
	uint8_t pinfield2[PINBLOCK128_SIZE];
	uint8_t panfield[PINBLOCK128_SIZE];
	uint8_t panfield2[PINBLOCK128_SIZE];
	uint8_t panfield3[PINBLOCK128_SIZE];
	unsigned int format;
	uint8_t decoded_pin[12];
	size_t decoded_pin_len = 0;

	// Test ISO 9564-1:2017 PIN block format 4 PIN field encoding
	r = pinblock_encode_iso9564_format4_pinfield(
		pin,
		sizeof(pin),
		pinfield
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_pinfield() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinfield, pinfield_verify, sizeof(pinfield_verify)) != 0) {
		fprintf(stderr, "PIN field is incorrect\n");
		print_buf("pinfield", pinfield, sizeof(pinfield));
		print_buf("pinfield_verify", pinfield_verify, sizeof(pinfield_verify));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 4 encoding randomness
	r = pinblock_encode_iso9564_format4_pinfield(
		pin,
		sizeof(pin),
		pinfield2
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinfield2, pinfield_verify, sizeof(pinfield_verify)) != 0) {
		fprintf(stderr, "PIN field is incorrect\n");
		print_buf("pinfield2", pinfield2, sizeof(pinfield2));
		print_buf("pinfield_verify", pinfield_verify, sizeof(pinfield_verify));
		r = 1;
		goto exit;
	}
	if (memcmp(pinfield, pinfield2, PINBLOCK128_SIZE) == 0) {
		fprintf(stderr, "PIN fields are not unique\n");
		print_buf("pinfield", pinfield, sizeof(pinfield));
		print_buf("pinfield2", pinfield2, sizeof(pinfield2));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 4 PAN field encoding
	r = pinblock_encode_iso9564_format4_panfield(
		pan,
		sizeof(pan),
		panfield
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(panfield, panfield_verify, sizeof(panfield_verify)) != 0) {
		fprintf(stderr, "PAN field is incorrect\n");
		print_buf("panfield", panfield, sizeof(panfield));
		print_buf("panfield_verify", panfield_verify, sizeof(panfield_verify));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 4 PIN field encoding odd number of PIN digits
	r = pinblock_encode_iso9564_format4_pinfield(
		pin2,
		sizeof(pin2),
		pinfield2
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_pinfield() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinfield2, pinfield_verify2, sizeof(pinfield_verify2)) != 0) {
		fprintf(stderr, "PIN field is incorrect\n");
		print_buf("pinfield2", pinfield2, sizeof(pinfield2));
		print_buf("pinfield_verify2", pinfield_verify2, sizeof(pinfield_verify2));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 4 PAN field encoding with padded PAN
	r = pinblock_encode_iso9564_format4_panfield(
		pan2,
		sizeof(pan2),
		panfield2
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(panfield2, panfield_verify2, sizeof(panfield_verify2)) != 0) {
		fprintf(stderr, "PAN field is incorrect\n");
		print_buf("panfield2", panfield2, sizeof(panfield2));
		print_buf("panfield_verify2", panfield_verify2, sizeof(panfield_verify2));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 4 PAN field encoding of short PAN with padding
	r = pinblock_encode_iso9564_format4_panfield(
		pan3,
		sizeof(pan3),
		panfield3
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(panfield3, panfield_verify3, sizeof(panfield_verify3)) != 0) {
		fprintf(stderr, "Short PAN field is incorrect\n");
		print_buf("panfield3", panfield3, sizeof(panfield3));
		print_buf("panfield_verify3", panfield_verify3, sizeof(panfield_verify3));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 4 decoding
	r = pinblock_decode_iso9564_format4_pinfield(
		pinfield,
		sizeof(pinfield),
		decoded_pin,
		&decoded_pin_len
	);
	if (r) {
		fprintf(stderr, "pinblock_decode_iso9564_format4_pinfield() failed; r=%d\n", r);
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
	r = pinblock_get_format(pinfield, sizeof(pinfield));
	if (r < 0) {
		fprintf(stderr, "pinblock_get_format() failed; r=%d\n", r);
		goto exit;
	}
	if (r != PINBLOCK_ISO9564_FORMAT_4) {
		fprintf(stderr, "Failed to retrieve PIN block format; r=%d\n", r);
		r = 1;
		goto exit;
	}

	// Test generic decoding
	r = pinblock_decode(
		pinfield,
		sizeof(pinfield),
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
	if (format != PINBLOCK_ISO9564_FORMAT_4) {
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
	pinfield[6] ^= 1;
	r = pinblock_decode_iso9564_format4_pinfield(
		pinfield,
		sizeof(pinfield),
		decoded_pin,
		&decoded_pin_len
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_decode_iso9564_format4_pinfield() unexpectedly succeeded with bad PIN block\n");
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
