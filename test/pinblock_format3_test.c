/**
 * @file pinblock_format3_test.c
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

// Hand made example
static const uint8_t pin[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
static const uint8_t pan[] = { 0x40, 0x12, 0x34, 0x56, 0x78, 0x90, 0x9F };
static const uint8_t pinblock_verify[] = { 0x35, 0x12 }; // This is as much as we can directly compare

static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

static int pinblock_iso9564_format3_verify(
	const uint8_t* pinblock,
	size_t pinblock_len,
	const uint8_t* pan,
	size_t pan_len
)
{
	uint8_t format;
	size_t decoded_pin_len;

	if (pinblock_len != PINBLOCK_SIZE) {
		// Invalid PIN block size
		return 1;
	}

	if (pan_len < 7) {
		// This function is unable to validate PIN blocks when the PAN has
		// fewer than 12 digits, excluding the check digit and padding digit,
		// thus 7 bytes
		return 2;
	}

	// First 4 bits are the control field indicating the PIN block format
	// See ISO 9564-1:2017 9.3.1
	format = pinblock[0] >> 4;
	if (format != PINBLOCK_ISO9564_FORMAT_3) {
		// Incorrect PIN block format
		return 3;
	}

	// Second 4 bits indicate PIN length
	// See ISO 9564-1:2017 9.3.5.2
	decoded_pin_len = pinblock[0] & 0xF;

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (decoded_pin_len < 4 || decoded_pin_len > 12) {
		return -2;
	}

	// Parse from the third nibble, which is where the PIN starts
	for (size_t i = 2; i < PINBLOCK_SIZE * 2 - 3; ++i) {
		uint8_t digit;

		// Extract PIN block digit
		if ((i & 0x1) == 0) { // Even digit index
			// Most significant nibble
			digit = pinblock[i >> 1] >> 4;
		} else {
			// Least significant nibble
			digit = pinblock[i >> 1] & 0xF;
		}

		// PAN field starts at fifth nibble
		if (i > 3) {
			size_t pan_idx;
			uint8_t pan_digit;
			// Extract digit
			if ((i & 0x1) == 0) { // Even digit index
				// Most significant nibble
				digit = pinblock[i >> 1] >> 4;
			} else {
				// Least significant nibble
				digit = pinblock[i >> 1] & 0xF;
			}

			// Determine PAN digit index
			if ((pan[pan_len - 1] & 0xF) == 0xF) {
				// Ignore PAN pad digit and check digit
				pan_idx = (pan_len - 1) * 2 - 2;
			} else {
				// Ignore PAN check digit
				pan_idx = (pan_len - 1) - 1;
			}
			pan_idx = (pan_idx - 12) + (i - 2);

			// Extract PAN digit
			if ((pan_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				pan_digit = pan[pan_idx >> 1] >> 4;
			} else {
				// Least significant nibble
				pan_digit = pan[pan_idx >> 1] & 0xF;
			}

			// Unmask digit
			digit ^= pan_digit;
		}

		if (i - 2 < decoded_pin_len) {
			// Validate PIN digit
			if (digit > 0x9) {
				// Invalid PIN digit
				return 1;
			}
		} else {
			// Validate nonce padding digit
			if (digit < 0xA || digit > 0xF) {
				// Invalid nonce padding digit
				return 2;
			}
		}
	}

	return 0;
}

int main(void)
{
	int r;
	uint8_t pinblock[PINBLOCK_SIZE];
	uint8_t pinblock2[PINBLOCK_SIZE];
	uint8_t format;
	uint8_t decoded_pin[12];
	size_t decoded_pin_len = 0;

	// Test ISO 9564-1:2017 PIN block format 3 encoding fill digit correctness
	r = pinblock_encode_iso9564_format3(
		pin,
		sizeof(pin),
		pan,
		sizeof(pan),
		pinblock
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format3() failed; r=%d\n", r);
		goto exit;
	}
	r = pinblock_iso9564_format3_verify(
		pinblock,
		sizeof(pinblock),
		pan,
		sizeof(pan)
	);
	if (r) {
		fprintf(stderr, "pinblock_iso9564_format3_verify() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinblock, pinblock_verify, sizeof(pinblock_verify)) != 0) {
		fprintf(stderr, "PIN block is incorrect\n");
		print_buf("pinblock", pinblock, sizeof(pinblock));
		print_buf("pinblock_verify", pinblock_verify, sizeof(pinblock_verify));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 3 encoding randomness
	r = pinblock_encode_iso9564_format3(
		pin,
		sizeof(pin),
		pan,
		sizeof(pan),
		pinblock2
	);
	if (r) {
		fprintf(stderr, "pinblock_encode_iso9564_format3() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(pinblock, pinblock2, PINBLOCK_SIZE) == 0) {
		fprintf(stderr, "PIN blocks are not unique\n");
		print_buf("pinblock", pinblock, sizeof(pinblock));
		print_buf("pinblock2", pinblock2, sizeof(pinblock2));
		r = 1;
		goto exit;
	}

	// Test ISO 9564-1:2017 PIN block format 3 decoding
	r = pinblock_decode_iso9564_format3(
		pinblock,
		sizeof(pinblock),
		pan,
		sizeof(pan),
		decoded_pin,
		&decoded_pin_len
	);
	if (r) {
		fprintf(stderr, "pinblock_decode_iso9564_format3() failed; r=%d\n", r);
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
	if (r != PINBLOCK_ISO9564_FORMAT_3) {
		fprintf(stderr, "Failed to retrieve PIN block format; r=%d\n", r);
		r = 1;
		goto exit;
	}

	// Test generic decoding
	r = pinblock_decode(
		pinblock,
		sizeof(pinblock),
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
	if (format != PINBLOCK_ISO9564_FORMAT_3) {
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

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
