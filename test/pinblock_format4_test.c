/**
 * @file pinblock_format4_test.c
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

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (Calculation of AES PIN Block Format 4; top of page 31)
static const uint8_t pin[] = { 0x01, 0x02, 0x03, 0x04 };
static const uint8_t pinfield_verify[] = { 0x44, 0x12, 0x34, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
static const uint8_t pan[] = { 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t panfield_verify[] = { 0x44, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Hand made example to test odd number of PIN digits and padded PAN
static const uint8_t pin2[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
static const uint8_t pinfield_verify2[] = { 0x45, 0x12, 0x34, 0x5A, 0xAA, 0xAA, 0xAA, 0xAA };
static const uint8_t pan2[] = { 0x41, 0x23, 0x45, 0x67, 0x89, 0x87, 0x65, 0x4F };
static const uint8_t panfield_verify2[] = { 0x34, 0x12, 0x34, 0x56, 0x78, 0x98, 0x76, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Hand made example to test 9-digit PAN with minimal padding
static const uint8_t pan3[] = { 0x12, 0x34, 0x56, 0x78, 0x9F };

// Hand made example to test 5-digit PAN with excessive padding
static const uint8_t pan4[] = { 0x12, 0x34, 0x5F, 0xFF, 0xFF, 0xFF, 0xFF };

// Hand made example to test PAN with all 0xF padding
static const uint8_t pan5[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// Hand made example to test PAN with invalid digits before padding
static const uint8_t pan6[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBF, 0xFF };

// Hand made example to test PAN with digits after padding
static const uint8_t pan7[] = { 0x12, 0x34, 0xF6, 0x78, 0x90, 0x12 };

// Hand made example to test PAN with invalid digit between valid digits
static const uint8_t pan8[] = { 0x12, 0x34, 0x5A, 0x67, 0x89, 0x01, 0x2F };

// Hand made example to test PAN with valid and invalid padding digits
static const uint8_t pan9[] = { 0x12, 0x3F, 0x45, 0x67, 0x89, 0x01, 0x2F };

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
	uint8_t panfield4[PINBLOCK128_SIZE];
	unsigned int format;
	uint8_t decoded_pin[12];
	size_t decoded_pin_len = 0;

	printf("Test 1: PIN field encoding of PIN with invalid digit...\n");
	r = pinblock_encode_iso9564_format4_pinfield(
		pin_invalid,
		sizeof(pin_invalid),
		pinfield
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_pinfield() unexpectedly succeeded for invalid PIN\n");
		r = 1;
		goto exit;
	}

	printf("Test 2: PIN field encoding of valid PIN...\n");
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

	printf("Test 3: PIN field encoding randomness...\n");
	r = pinblock_encode_iso9564_format4_pinfield(
		pin,
		sizeof(pin),
		pinfield2
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_pinfield() failed; r=%d\n", r);
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

	printf("Test 4: PAN field encoding of 16-digit PAN with no padding...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan,
		sizeof(pan),
		panfield
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() failed; r=%d\n", r);
		print_buf("pan", pan, sizeof(pan));
		goto exit;
	}
	if (memcmp(panfield, panfield_verify, sizeof(panfield_verify)) != 0) {
		fprintf(stderr, "PAN field is incorrect\n");
		print_buf("panfield", panfield, sizeof(panfield));
		print_buf("panfield_verify", panfield_verify, sizeof(panfield_verify));
		r = 1;
		goto exit;
	}

	printf("Test 5: PIN field encoding with odd number of PIN digits...\n");
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

	printf("Test 6: PAN field encoding of 15-digit PAN with minimal padding...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan2,
		sizeof(pan2),
		panfield2
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() failed; r=%d\n", r);
		print_buf("pan2", pan2, sizeof(pan2));
		goto exit;
	}
	if (memcmp(panfield2, panfield_verify2, sizeof(panfield_verify2)) != 0) {
		fprintf(stderr, "PAN field is incorrect\n");
		print_buf("panfield2", panfield2, sizeof(panfield2));
		print_buf("panfield_verify2", panfield_verify2, sizeof(panfield_verify2));
		r = 1;
		goto exit;
	}

	printf("Test 7: PAN field encoding of 9-digit PAN...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan3,
		sizeof(pan3),
		panfield3
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with 9-digit PAN\n");
		print_buf("pan3", pan3, sizeof(pan3));
		r = 1;
		goto exit;
	}

	printf("Test 8: PAN field encoding of 5-digit PAN padded to 7 bytes...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan4,
		sizeof(pan4),
		panfield4
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with 5-digit PAN\n");
		print_buf("pan4", pan4, sizeof(pan4));
		r = 1;
		goto exit;
	}

	printf("Test 9: PAN field encoding of all 0xF PAN...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan5,
		sizeof(pan5),
		panfield
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with all 0xF PAN\n");
		print_buf("pan5", pan5, sizeof(pan5));
		r = 1;
		goto exit;
	}

	printf("Test 10: PAN field encoding of PAN with invalid digits...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan6,
		sizeof(pan6),
		panfield
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with invalid PAN digits before padding\n");
		print_buf("pan6", pan6, sizeof(pan6));
		r = 1;
		goto exit;
	}

	printf("Test 11: PAN field encoding of PAN with digits after padding...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan7,
		sizeof(pan7),
		panfield
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with PAN digits after padding\n");
		print_buf("pan7", pan7, sizeof(pan7));
		r = 1;
		goto exit;
	}

	printf("Test 12: PAN field encoding of PAN with invalid digit...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan8,
		sizeof(pan8),
		panfield
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with invalid PAN digit\n");
		print_buf("pan8", pan8, sizeof(pan8));
		r = 1;
		goto exit;
	}

	printf("Test 13: PAN field encoding of PAN with valid and invalid padding digits...\n");
	r = pinblock_encode_iso9564_format4_panfield(
		pan9,
		sizeof(pan9),
		panfield
	);
	if (r == 0) {
		fprintf(stderr, "pinblock_encode_iso9564_format4_panfield() unexpectedly succeeded with invalid PAN padding digits\n");
		print_buf("pan9", pan9, sizeof(pan9));
		r = 1;
		goto exit;
	}

	printf("Test 14: PIN field format 4 decoding...\n");
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

	printf("Test 15: PIN block format retrieval...\n");
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

	printf("Test 16: Generic PIN field decoding...\n");
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

	printf("Test 17: PIN block padding validation...\n");
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
