/**
 * @file pinblock.c
 * @brief ISO 9564-1:2017 PIN block format implementation
 *
 * Copyright (c) 2022 Leon Lynch
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "pinblock.h"

#include <stdbool.h>
#include <string.h>

#include "crypto_mem.h"

static void pinblock_pack_pin(uint8_t format, const uint8_t* pin, size_t pin_len, uint8_t fill_digit, uint8_t* pinblock)
{
	// Sanitise PIN length
	pin_len &= 0x0F;

	// Pad using fill digit
	// See ISO 9564-1:2017 9.3.2.2
	memset(pinblock, (fill_digit << 4) | fill_digit, PINBLOCK_SIZE);

	// Pack PIN digits
	// See ISO 9564-1:2017 9.3.2.2
	pinblock[0] = (format << 4) | pin_len;
	for (size_t i = 0; i < pin_len; ++i) {
		if ((i & 0x1) == 0) { // Even digit index
			// Most significant nibble
			pinblock[(i >> 1) + 1] = pin[i] << 4;
		} else { // Odd digit index
			// Least significant nibble
			pinblock[(i >> 1) + 1] |= pin[i] & 0x0F;
		}
	}

	// Pad using fill digit
	// See ISO 9564-1:2017 9.3.2.2
	fill_digit &= 0x0F;
	if (pin_len & 0x1) { // Odd PIN length
		// Pad remaining nibble if odd PIN length
		pinblock[(pin_len >> 1) + 1] |= fill_digit;
	}
}

static void pinblock_unpack_pin(const uint8_t* pinblock, uint8_t* pin, size_t pin_len)
{
	// For ISO 956401:2017 PIN block formats, the PIN starts at the second byte
	for (size_t i = 0; i < pin_len; ++i) {
		uint8_t digit;

		// Extract PIN digit
		if ((i & 0x1) == 0) { // Even digit index
			// Most significant nibble
			digit = pinblock[(i >> 1) + 1] >> 4;
		} else { // Odd digit index
			// Least significant nibble
			digit = pinblock[(i >> 1) + 1] & 0x0F;
		}

		*pin = digit;
		++pin;
	}
}

static void pinblock_pack_pan(const uint8_t* pan, size_t pan_len, uint8_t* panfield)
{
	size_t panfield_len = PINBLOCK_SIZE;
	size_t pan_idx = 0;
	size_t panfield_idx = 0;
	bool check_digit_found = false;

	// Pad using zeros
	// See ISO 9564-1:2017 9.3.2.3
	// See ISO 9564-1:2017 9.3.5.3
	memset(panfield, 0, PINBLOCK_SIZE);

	// Pack 12 digits of PAN, excluding padding and check digit, starting with
	// the rightmost byte
	while (pan_len > 0 && panfield_len > 0 && panfield_idx < 12) {
		uint8_t digit;

		// Extract PAN digit
		if ((pan_idx & 0x1) == 0) { // Even digit index
			// Least significant nibble
			digit = pan[pan_len - 1] & 0xF;
		} else { // Odd digit index
			// Most significant nibble
			digit = pan[pan_len - 1] >> 4;
			--pan_len;
		}
		++pan_idx;

		// Skip over padding
		if (digit == 0xF) {
			continue;
		}

		// Skip over check digit
		if (!check_digit_found) {
			check_digit_found = true;
			continue;
		}

		// Pack digit into PAN block
		// See ISO 9564-1:2017 9.3.2.3
		// See ISO 9564-1:2017 9.3.5.3
		if ((panfield_idx & 0x1) == 0) { // Even digit index
			// Least significant nibble
			panfield[panfield_len - 1] = digit;
		} else { // Odd digit index
			// Most significant nibble
			panfield[panfield_len - 1] |= (digit << 4);
			--panfield_len;
		}
		++panfield_idx;
	}
}

int pinblock_encode_iso9564_format0(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinblock
)
{
	uint8_t panfield[PINBLOCK_SIZE];

	if (!pin || !pin_len || !pan || !pan_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < 4 || pin_len > 12) {
		return -2;
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.2.2
	pinblock_pack_pin(PINBLOCK_ISO9564_FORMAT_0, pin, pin_len, 0xF, pinblock);

	// Build PAN field
	// See ISO 9564-1:2017 9.3.2.3
	pinblock_pack_pan(pan, pan_len, panfield);

	// Build PIN block
	// See ISO 9564-1:2017 9.3.2.1
	crypto_xor(pinblock, panfield, PINBLOCK_SIZE);

	crypto_cleanse(panfield, sizeof(panfield));

	return 0;
}

int pinblock_decode_iso9564_format0(
	const uint8_t* pinblock,
	size_t pinblock_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	uint8_t format;
	size_t decoded_pin_len;
	uint8_t pinfield[PINBLOCK_SIZE];
	uint8_t panfield[PINBLOCK_SIZE];

	if (!pinblock || !pinblock_len || !pan || !pan_len || !pin || !pin_len) {
		return -1;
	}
	*pin_len = 0;

	if (pinblock_len != PINBLOCK_SIZE) {
		// Invalid PIN block size
		return 1;
	}

	// First 4 bits are the control field indicating the PIN block format
	// See ISO 9564-1:2017 9.3.1
	format = pinblock[0] >> 4;
	if (format != PINBLOCK_ISO9564_FORMAT_0) {
		// Incorrect PIN block format
		return 2;
	}

	// Second 4 bits indicate PIN length
	// See ISO 9564-1:2017 9.3.2.2
	decoded_pin_len = pinblock[0] & 0xF;

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (decoded_pin_len < 4 || decoded_pin_len > 12) {
		return -2;
	}

	// Extract PIN field from PIN block
	// See ISO 9564-1:2017 9.3.2.1
	memcpy(pinfield, pinblock, PINBLOCK_SIZE);
	pinblock_pack_pan(pan, pan_len, panfield);
	crypto_xor(pinfield, panfield, PINBLOCK_SIZE);

	// Sanity check
	if (memcmp(pinblock, pinfield, 2) != 0) {
		crypto_cleanse(pinfield, sizeof(pinfield));
		crypto_cleanse(panfield, sizeof(panfield));
		return -3;
	}

	pinblock_unpack_pin(pinfield, pin, decoded_pin_len);
	*pin_len = decoded_pin_len;

	crypto_cleanse(pinfield, sizeof(pinfield));
	crypto_cleanse(panfield, sizeof(panfield));

	return 0;
}

int pinblock_get_format(const uint8_t* pinblock, size_t pinblock_len)
{
	uint8_t format;

	if (pinblock_len == PINBLOCK_SIZE) {
		// First 4 bits are the control field indicating the PIN block format
		// See ISO 9564-1:2017 9.3.1
		format = pinblock[0] >> 4;

		switch (format) {
			case PINBLOCK_ISO9564_FORMAT_0:
			case PINBLOCK_ISO9564_FORMAT_1:
			case PINBLOCK_ISO9564_FORMAT_2:
			case PINBLOCK_ISO9564_FORMAT_3:
				return format;
		}
	}

	return -1;
}

int pinblock_decode(
	const uint8_t* pinblock,
	size_t pinblock_len,
	const uint8_t* other,
	size_t other_len,
	uint8_t* format,
	uint8_t* pin,
	size_t* pin_len
)
{
	if (!pinblock || !pinblock_len || !format || !pin || !pin_len) {
		return -1;
	}

	if (pinblock_len != PINBLOCK_SIZE) {
		// Unsupported PIN block size
		return 1;
	}

	// First 4 bits are the control field indicating the PIN block format
	// See ISO 9564-1:2017 9.3.1
	*format = pinblock[0] >> 4;
	switch (*format) {
		case PINBLOCK_ISO9564_FORMAT_0:
			return pinblock_decode_iso9564_format0(
				pinblock,
				pinblock_len,
				other,
				other_len,
				pin,
				pin_len
			);

		default:
			return 5;
	}
}
