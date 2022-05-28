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
#include "crypto_rand.h"

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

static void pinblock_pack_pin_with_nonce(uint8_t format, const uint8_t* pin, size_t pin_len, const uint8_t* nonce, size_t nonce_len, uint8_t* pinblock)
{
	// Sanitise PIN length
	pin_len &= 0x0F;

	// Pack PIN digits
	// See ISO 9564-1:2017 9.3.3
	// See ISO 9564-1:2017 9.3.5.2
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

	// Pad using nonce
	for (size_t i = pin_len; i < (PINBLOCK_SIZE - 1) * 2 && nonce_len; ++i) {
		uint8_t digit;

		// Extract nonce digit
		size_t nonce_idx = i - pin_len;
		if ((nonce_idx & 0x1) == 0) { // Even digit index
			// Most significant nibble
			digit = nonce[nonce_idx >> 1] >> 4;
		} else { // Odd digit index
			// Least significant nibble
			digit = nonce[nonce_idx >> 1] & 0xF;
			--nonce_len;
		}
		++nonce_idx;

		// Pack nonce digit into PIN block
		// See ISO 9564-1:2017 9.3.3
		// See ISO 9564-1:2017 9.3.5.2
		if ((i & 0x1) == 0) { // Even digit index
			// Most significant nibble
			pinblock[(i >> 1) + 1] = digit << 4;
		} else { // Odd digit index
			// Least significant nibble
			pinblock[(i >> 1) + 1] |= digit;
		}
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

		// Pack digit into PAN field
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

int pinblock_encode_iso9564_format1(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* nonce,
	size_t nonce_len,
	uint8_t* pinblock
)
{
	uint8_t nonce_field[PINBLOCK_SIZE];

	if (!pin || !pin_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < 4 || pin_len > 12) {
		return -2;
	}

	// Validate nonce length
	// See ISO 9564-1:2017 9.3.3
	if (nonce && nonce_len && nonce_len < PINBLOCK_SIZE - 1 - (pin_len / 2)) {
		return -3;
	}

	// Build nonce field
	if (!nonce) {
		// No nonce provided; build random nonce
		nonce_len = PINBLOCK_SIZE - 1 - (pin_len / 2);
		crypto_rand(nonce_field, nonce_len);
	} else {
		// Populate nonce field in reverse to ensure that the least significant
		// bytes are used if the nonce is actually the transaction sequence
		// number (EMV field 9F41)
		for (size_t i = 0; i < sizeof(nonce_field) && i < nonce_len; ++i) {
			nonce_field[i] = nonce[nonce_len - 1 - i];
		}
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.3
	pinblock_pack_pin_with_nonce(PINBLOCK_ISO9564_FORMAT_1, pin, pin_len, nonce_field, nonce_len, pinblock);

	crypto_cleanse(nonce_field, sizeof(nonce_field));

	return 0;
}

int pinblock_decode_iso9564_format1(
	const uint8_t* pinblock,
	size_t pinblock_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	uint8_t format;
	size_t decoded_pin_len;

	if (!pinblock || !pinblock_len || !pin || !pin_len) {
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
	if (format != PINBLOCK_ISO9564_FORMAT_1) {
		// Incorrect PIN block format
		return 2;
	}

	// Second 4 bits indicate PIN length
	// See ISO 9564-1:2017 9.3.3
	decoded_pin_len = pinblock[0] & 0xF;

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (decoded_pin_len < 4 || decoded_pin_len > 12) {
		return -2;
	}

	pinblock_unpack_pin(pinblock, pin, decoded_pin_len);
	*pin_len = decoded_pin_len;

	return 0;
}

int pinblock_encode_iso9564_format2(
	const uint8_t* pin,
	size_t pin_len,
	uint8_t* pinblock
)
{
	if (!pin || !pin_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < 4 || pin_len > 12) {
		return -2;
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.4
	pinblock_pack_pin(PINBLOCK_ISO9564_FORMAT_2, pin, pin_len, 0xF, pinblock);

	return 0;
}

int pinblock_decode_iso9564_format2(
	const uint8_t* pinblock,
	size_t pinblock_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	uint8_t format;
	size_t decoded_pin_len;

	if (!pinblock || !pinblock_len || !pin || !pin_len) {
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
	if (format != PINBLOCK_ISO9564_FORMAT_2) {
		// Incorrect PIN block format
		return 2;
	}

	// Second 4 bits indicate PIN length
	// See ISO 9564-1:2017 9.3.4
	decoded_pin_len = pinblock[0] & 0xF;

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (decoded_pin_len < 4 || decoded_pin_len > 12) {
		return -2;
	}

	pinblock_unpack_pin(pinblock, pin, decoded_pin_len);
	*pin_len = decoded_pin_len;

	return 0;
}

int pinblock_encode_iso9564_format3(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinblock
)
{
	uint8_t nonce_input[10];
	uint8_t nonce[5];
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

	// Build 5 byte nonce consisting only of nibbles from 0xA to 0xF
	// using input of 10 random bytes
	// See ISO 9564-1:2017 9.3.5.2
	crypto_rand(nonce_input, sizeof(nonce_input));
	for (size_t i = 0; i < sizeof(nonce); ++i) {
		uint8_t scaled_nonce;

		// Scale nonce input to range from 0xA to 0xF
		scaled_nonce = ((((uint16_t)nonce_input[i * 2]) * 6) >> 8) + 0xA;

		// Pack most significant nibble
		nonce[i] = scaled_nonce << 4;

		// Scale next nonce input to range from 0xA to 0xF
		scaled_nonce = ((((uint16_t)nonce_input[i * 2 + 1]) * 6) >> 8) + 0xA;

		// Pack most significant nibble
		nonce[i] |= scaled_nonce & 0xF;
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.5.2
	pinblock_pack_pin_with_nonce(PINBLOCK_ISO9564_FORMAT_3, pin, pin_len, nonce, sizeof(nonce), pinblock);

	// Build PAN field
	// See ISO 9564-1:2017 9.3.5.3
	pinblock_pack_pan(pan, pan_len, panfield);

	// Build PIN block
	// See ISO 9564-1:2017 9.3.5.1
	crypto_xor(pinblock, panfield, PINBLOCK_SIZE);

	crypto_cleanse(nonce_input, sizeof(nonce_input));
	crypto_cleanse(nonce, sizeof(nonce));
	crypto_cleanse(panfield, sizeof(panfield));

	return 0;
}

int pinblock_decode_iso9564_format3(
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
	if (format != PINBLOCK_ISO9564_FORMAT_3) {
		// Incorrect PIN block format
		return 2;
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

	// Extract PIN field from PIN block
	// See ISO 9564-1:2017 9.3.5.1
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

int pinblock_encode_iso9564_format4_pinfield(
	const uint8_t* pin,
	size_t pin_len,
	uint8_t* pinfield
)
{
	if (!pin || !pin_len || !pinfield) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < 4 || pin_len > 12) {
		return -2;
	}

	// Build PIN field (first 8 bytes)
	// See ISO 9564-1:2017 9.4.2.2.2
	pinblock_pack_pin(PINBLOCK_ISO9564_FORMAT_4, pin, pin_len, 0xA, pinfield);

	// Build PIN field (last 8 bytes)
	// See ISO 9564-1:2017 9.4.2.2.2
	crypto_rand(pinfield + PINBLOCK128_SIZE / 2, PINBLOCK128_SIZE / 2);

	return 0;
}

int pinblock_encode_iso9564_format4_panfield(
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* panfield
)
{
	if (!pan || !pan_len || !panfield) {
		return -1;
	}

	// Build PAN field
	// See ISO 9564-1:2017 9.4.2.2.3
	memset(panfield, 0, PINBLOCK128_SIZE);
	if (pan_len < 6 ||
		(pan_len == 6 &&(pan[pan_len - 1] & 0xF) == 0xF)
	) {
		// If PAN is less than 12 digits, M is zero
		// PAN digits will be right justified and left padded with zeros

		size_t pan_idx = 0;
		size_t panfield_idx = 12; // Start after M digit

		while (pan_len > 0 && panfield_idx > 0) {
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

			// Pack digit into PAN field
			// See ISO 9564-1:2017 9.3.2.3
			// See ISO 9564-1:2017 9.3.5.3
			if ((panfield_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				panfield[panfield_idx >> 1] |= (digit << 4);
			} else { // Odd digit index
				// Least significant nibble
				panfield[panfield_idx >> 1] = digit;
			}
			--panfield_idx;
		}

	} else {
		// If PAN is 12 or more digits, M is number of digits beyond 12
		// NOTE: In contrast to ISO 9564-1:2017 PIN block format 0/3, format 4
		// does not ignore the PAN check digit

		size_t panfield_len = PINBLOCK128_SIZE - 6; // Last 6 bytes are zero'd
		size_t pan_idx = 0;
		size_t panfield_idx = 1; // Start after M digit

		while (pan_len > 0 && panfield_len > 0) {
			uint8_t digit;

			// Extract PAN digit
			if ((pan_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				digit = pan[pan_idx >> 1] >> 4;
			} else { // Odd digit index
				// Least significant nibble
				digit = pan[pan_idx >> 1] & 0xF;
				--pan_len;
			}

			// Skip over padding
			if (digit == 0xF) {
				break;
			}

			// Valid PAN digit
			++pan_idx;

			// Pack digit into PAN field
			// See ISO 9564-1:2017 9.4.2.2.3
			if ((panfield_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				panfield[panfield_idx >> 1] = (digit << 4);
			} else { // Odd digit index
				// Least significant nibble
				panfield[panfield_idx >> 1] |= digit;
				--panfield_len;
			}
			++panfield_idx;
		}

		// Populate M
		panfield[0] |= (pan_idx - 12) << 4;
	}

	return 0;
}

int pinblock_decode_iso9564_format4_pinfield(
	const uint8_t* pinfield,
	size_t pinfield_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	uint8_t format;
	size_t decoded_pin_len;

	if (!pinfield || !pin || !pin_len) {
		return -1;
	}
	*pin_len = 0;

	if (pinfield_len != PINBLOCK128_SIZE) {
		// Invalid PIN block size
		return 1;
	}

	// First 4 bits are the control field indicating the PIN block format
	// See ISO 9564-1:2017 9.3.1
	format = pinfield[0] >> 4;
	if (format != PINBLOCK_ISO9564_FORMAT_4) {
		// Incorrect PIN block format
		return 2;
	}

	// Second 4 bits indicate PIN length
	// See ISO 9564-1:2017 9.3.2.2
	decoded_pin_len = pinfield[0] & 0xF;

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (decoded_pin_len < 4 || decoded_pin_len > 12) {
		return -2;
	}

	// Decode PIN
	pinblock_unpack_pin(pinfield, pin, decoded_pin_len);
	*pin_len = decoded_pin_len;

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

	} else if (pinblock_len == PINBLOCK128_SIZE) {
		// First 4 bits are the control field indicating the PIN block format
		// See ISO 9564-1:2017 9.4.2.2.2
		format = pinblock[0] >> 4;

		switch (format) {
			case PINBLOCK_ISO9564_FORMAT_4:
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
	unsigned int* format,
	uint8_t* pin,
	size_t* pin_len
)
{
	if (!pinblock || !pinblock_len || !format || !pin || !pin_len) {
		return -1;
	}

	if (pinblock_len == PINBLOCK_SIZE) {
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

			case PINBLOCK_ISO9564_FORMAT_1:
				return pinblock_decode_iso9564_format1(
					pinblock,
					pinblock_len,
					pin,
					pin_len
				);

			case PINBLOCK_ISO9564_FORMAT_2:
				return pinblock_decode_iso9564_format2(
					pinblock,
					pinblock_len,
					pin,
					pin_len
				);

			case PINBLOCK_ISO9564_FORMAT_3:
				return pinblock_decode_iso9564_format3(
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

	} else if (pinblock_len == PINBLOCK128_SIZE) {
		// First 4 bits are the control field indicating the PIN block format
		// See ISO 9564-1:2017 9.4.2.2.2
		// First 4 bits are the control field indicating the PIN block format
		// See ISO 9564-1:2017 9.4.2.2.2
		*format = pinblock[0] >> 4;

		switch (*format) {
			case PINBLOCK_ISO9564_FORMAT_4:
				return pinblock_decode_iso9564_format4_pinfield(
					pinblock,
					pinblock_len,
					pin,
					pin_len
				);
		}
	}

	// Unsupported PIN block size
	return 1;
}
