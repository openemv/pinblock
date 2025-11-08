/**
 * @file pinblock.c
 * @brief ISO 9564-1:2017 PIN block format implementation
 *
 * Copyright 2022, 2025 Leon Lynch
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

static int pinblock_pack_pin(
	uint8_t format,
	const uint8_t* pin,
	size_t pin_len,
	uint8_t fill_digit,
	uint8_t* pinblock
)
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
		if (pin[i] > 9) {
			// Invalid PIN digit
			return 1;
		}

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

	return 0;
}

static int pinblock_pack_pin_with_nonce(
	uint8_t format,
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* nonce,
	size_t nonce_len,
	uint8_t* pinblock
)
{
	// Sanitise PIN length
	pin_len &= 0x0F;

	// Pack PIN digits
	// See ISO 9564-1:2017 9.3.3
	// See ISO 9564-1:2017 9.3.5.2
	pinblock[0] = (format << 4) | pin_len;
	for (size_t i = 0; i < pin_len; ++i) {
		if (pin[i] > 9) {
			// Invalid PIN digit
			return 1;
		}

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

	return 0;
}

static int pinblock_unpack_pin(
	uint8_t format,
	const uint8_t* pinblock,
	uint8_t* pin,
	size_t* pin_len
)
{
	size_t decoded_pin_len;

	switch (format) {
		case PINBLOCK_ISO9564_FORMAT_0:
		case PINBLOCK_ISO9564_FORMAT_1:
		case PINBLOCK_ISO9564_FORMAT_2:
		case PINBLOCK_ISO9564_FORMAT_3:
		case PINBLOCK_ISO9564_FORMAT_4:
			break;

		default:
			// Unsupported PIN block format
			return -4;
	}

	// First 4 bits are the control field indicating the PIN block format
	// See ISO 9564-1:2017 9.3.1
	if (pinblock[0] >> 4 != format) {
		// Incorrect PIN block format
		return 2;
	}

	// Second 4 bits indicate PIN length
	// See ISO 9564-1:2017 9.3.2.2
	// See ISO 9564-1:2017 9.3.3
	// See ISO 9564-1:2017 9.3.4
	// See ISO 9564-1:2017 9.3.5.2
	// See ISO 9564-1:2017 9.4.2.2.2
	decoded_pin_len = pinblock[0] & 0xF;

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (decoded_pin_len < PINBLOCK_PIN_LENGTH_MIN ||
		decoded_pin_len > PINBLOCK_PIN_LENGTH_MAX
	) {
		return -5;
	}

	// Decode PIN and validate padding
	// For ISO 9564-1:2017 PIN block formats, the PIN starts at the second byte
	// and padding is only up to the first 8 bytes (16 digits), even for PIN
	// block format 4
	for (size_t i = 0; i < 13; ++i) { // Iterate from 3rd digit to 16th digit
		uint8_t digit;

		// Extract digit
		if ((i & 0x1) == 0) { // Even digit index
			// Most significant nibble
			digit = pinblock[(i >> 1) + 1] >> 4;
		} else { // Odd digit index
			// Least significant nibble
			digit = pinblock[(i >> 1) + 1] & 0x0F;
		}

		if (i < decoded_pin_len) {
			// Validate PIN digit
			if (digit > 0x9) {
				// Invalid PIN digit; either decrypt key or PAN were likely incorrect
				return -6;
			}

			// Append PIN digit
			*pin = digit;
			++pin;
		} else {
			// Validate padding digit
			switch (format) {
				case PINBLOCK_ISO9564_FORMAT_0:
				case PINBLOCK_ISO9564_FORMAT_2:
					// See ISO 9564-1:2017 9.3.2.2
					// See ISO 9564-1:2017 9.3.4
					if (digit != 0xF) {
						// Invalid padding digit; either decrypt key or PAN were likely incorrect
						return -7;
					}
					break;

				case PINBLOCK_ISO9564_FORMAT_3:
					// See ISO 9564-1:2017 9.3.5.2
					if (digit < 0xA) {
						// Invalid padding digit; either decrypt key or PAN were likely incorrect
						return -7;
					}
					break;

				case PINBLOCK_ISO9564_FORMAT_4:
					// See ISO 9564-1:2017 9.4.2.2.2
					if (digit != 0xA) {
						// Invalid padding digit; either decrypt key or PAN were likely incorrect
						return -7;
					}
					break;
			}
		}
	}

	*pin_len = decoded_pin_len;
	return 0;
}

static int pinblock_pack_pan(
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* panfield
)
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

		// Padding is only allowed after check digit
		if (!check_digit_found) {
			if (digit >= 0xA && digit <= 0xE) {
				// Invalid PAN digit
				return 1;
			}

			// Skip over trailing padding
			if (digit == 0xF) {
				continue;
			}

			// Skip over check digit
			check_digit_found = true;
			continue;

		} else {
			// No more padding or check digit
			if (digit > 9) {
				// Invalid PAN digit
				return 2;
			}
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

	// Validate PAN length
	// ISO 9564-1:2017 does not specify minimum or maximum PAN lengths.
	// However, ISO 7812 specifies that PANs are 10 - 19 digits and the number
	// of available PAN digits may impact the PAN encoding. It is therefore
	// reasonable to reject invalid PAN lengths.
	if (panfield_idx < 10) {
		return 3;
	}
	if (panfield_idx > 19) {
		return 4;
	}

	return 0;
}

int pinblock_encode_iso9564_format0(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinblock
)
{
	int r;
	uint8_t panfield[PINBLOCK_SIZE];

	if (!pin || !pin_len || !pan || !pan_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < PINBLOCK_PIN_LENGTH_MIN ||
		pin_len > PINBLOCK_PIN_LENGTH_MAX
	) {
		r = -2;
		goto error;
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.2.2
	r = pinblock_pack_pin(PINBLOCK_ISO9564_FORMAT_0, pin, pin_len, 0xF, pinblock);
	if (r) {
		r = -3;
		goto error;
	}

	// Build PAN field
	// See ISO 9564-1:2017 9.3.2.3
	r = pinblock_pack_pan(pan, pan_len, panfield);
	if (r) {
		r = -4;
		goto error;
	}

	// Build PIN block
	// See ISO 9564-1:2017 9.3.2.1
	crypto_xor(pinblock, panfield, PINBLOCK_SIZE);

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that PIN block is unusable on error
	crypto_rand(pinblock, PINBLOCK_SIZE);
exit:
	// Cleanup
	crypto_cleanse(panfield, sizeof(panfield));
	return r;
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
	int r;
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

	// Extract PIN field from PIN block
	// See ISO 9564-1:2017 9.3.2.1
	memcpy(pinfield, pinblock, PINBLOCK_SIZE);
	r = pinblock_pack_pan(pan, pan_len, panfield);
	if (r) {
		r = -2;
		goto error;
	}
	crypto_xor(pinfield, panfield, PINBLOCK_SIZE);

	// Sanity check
	if (memcmp(pinblock, pinfield, 2) != 0) {
		r = -3;
		goto error;
	}

	r = pinblock_unpack_pin(PINBLOCK_ISO9564_FORMAT_0, pinfield, pin, pin_len);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pin, PINBLOCK_PIN_LENGTH_MAX);
exit:
	crypto_cleanse(pinfield, sizeof(pinfield));
	crypto_cleanse(panfield, sizeof(panfield));

	return r;
}

int pinblock_encode_iso9564_format1(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* nonce,
	size_t nonce_len,
	uint8_t* pinblock
)
{
	int r;
	uint8_t nonce_field[PINBLOCK_SIZE];

	if (!pin || !pin_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < PINBLOCK_PIN_LENGTH_MIN ||
		pin_len > PINBLOCK_PIN_LENGTH_MAX
	) {
		r = -2;
		goto error;
	}

	// Validate nonce length
	// See ISO 9564-1:2017 9.3.3
	if (nonce && nonce_len && nonce_len < PINBLOCK_SIZE - 1 - (pin_len / 2)) {
		r = -3;
		goto error;
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
	r = pinblock_pack_pin_with_nonce(PINBLOCK_ISO9564_FORMAT_1, pin, pin_len, nonce_field, nonce_len, pinblock);
	if (r) {
		r = -4;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that PIN block is unusable on error
	crypto_rand(pinblock, PINBLOCK_SIZE);
exit:
	// Cleanup
	crypto_cleanse(nonce_field, sizeof(nonce_field));
	return r;
}

int pinblock_decode_iso9564_format1(
	const uint8_t* pinblock,
	size_t pinblock_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	int r;

	if (!pinblock || !pinblock_len || !pin || !pin_len) {
		return -1;
	}
	*pin_len = 0;

	if (pinblock_len != PINBLOCK_SIZE) {
		// Invalid PIN block size
		return 1;
	}

	r = pinblock_unpack_pin(PINBLOCK_ISO9564_FORMAT_1, pinblock, pin, pin_len);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pin, PINBLOCK_PIN_LENGTH_MAX);
exit:
	return r;
}

int pinblock_encode_iso9564_format2(
	const uint8_t* pin,
	size_t pin_len,
	uint8_t* pinblock
)
{
	int r;

	if (!pin || !pin_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < PINBLOCK_PIN_LENGTH_MIN ||
		pin_len > PINBLOCK_PIN_LENGTH_MAX
	) {
		r = -2;
		goto error;
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.4
	r = pinblock_pack_pin(PINBLOCK_ISO9564_FORMAT_2, pin, pin_len, 0xF, pinblock);
	if (r) {
		r = -3;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that PIN block is unusable on error
	crypto_rand(pinblock, PINBLOCK_SIZE);
exit:
	return r;
}

int pinblock_decode_iso9564_format2(
	const uint8_t* pinblock,
	size_t pinblock_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	int r;

	if (!pinblock || !pinblock_len || !pin || !pin_len) {
		return -1;
	}
	*pin_len = 0;

	if (pinblock_len != PINBLOCK_SIZE) {
		// Invalid PIN block size
		return 1;
	}

	r = pinblock_unpack_pin(PINBLOCK_ISO9564_FORMAT_2, pinblock, pin, pin_len);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pin, PINBLOCK_PIN_LENGTH_MAX);
exit:
	return r;
}

int pinblock_encode_iso9564_format3(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinblock
)
{
	int r;
	uint8_t nonce[5];
	uint8_t panfield[PINBLOCK_SIZE];

	if (!pin || !pin_len || !pan || !pan_len || !pinblock) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < PINBLOCK_PIN_LENGTH_MIN ||
		pin_len > PINBLOCK_PIN_LENGTH_MAX
	) {
		r = -2;
		goto error;
	}

	// Build 5 byte nonce consisting only of nibbles from 0xA to 0xF
	// See ISO 9564-1:2017 9.3.5.2
	for (size_t i = 0; i < sizeof(nonce); ++i) {
		uint8_t nonce_digit;

		r = crypto_rand_byte(0xA, 0xF);
		if (r < 0) {
			r = -3;
			goto error;
		}
		if (r < 0xA || r > 0xF) {
			r = -4;
			goto error;
		}
		nonce_digit = r;

		// Pack most significant nibble
		nonce[i] = nonce_digit << 4;

		r = crypto_rand_byte(0xA, 0xF);
		if (r < 0) {
			r = -5;
			goto error;
		}
		if (r < 0xA || r > 0xF) {
			r = -6;
			goto error;
		}
		nonce_digit = r;

		// Pack least significant nibble
		nonce[i] |= nonce_digit & 0xF;

		crypto_cleanse(&nonce_digit, sizeof(nonce_digit));
	}

	// Build PIN field
	// See ISO 9564-1:2017 9.3.5.2
	r = pinblock_pack_pin_with_nonce(PINBLOCK_ISO9564_FORMAT_3, pin, pin_len, nonce, sizeof(nonce), pinblock);
	if (r) {
		r = -7;
		goto error;
	}

	// Build PAN field
	// See ISO 9564-1:2017 9.3.5.3
	r = pinblock_pack_pan(pan, pan_len, panfield);
	if (r) {
		r = -8;
		goto error;
	}

	// Build PIN block
	// See ISO 9564-1:2017 9.3.5.1
	crypto_xor(pinblock, panfield, PINBLOCK_SIZE);

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that PIN block is unusable on error
	crypto_rand(pinblock, PINBLOCK_SIZE);
exit:
	// Cleanup
	crypto_cleanse(nonce, sizeof(nonce));
	crypto_cleanse(panfield, sizeof(panfield));
	return r;
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
	int r;
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

	// Extract PIN field from PIN block
	// See ISO 9564-1:2017 9.3.5.1
	memcpy(pinfield, pinblock, PINBLOCK_SIZE);
	r = pinblock_pack_pan(pan, pan_len, panfield);
	if (r) {
		r = -2;
		goto error;
	}
	crypto_xor(pinfield, panfield, PINBLOCK_SIZE);

	// Sanity check
	if (memcmp(pinblock, pinfield, 2) != 0) {
		r = -3;
		goto error;
	}

	r = pinblock_unpack_pin(PINBLOCK_ISO9564_FORMAT_3, pinfield, pin, pin_len);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pin, PINBLOCK_PIN_LENGTH_MAX);
exit:
	crypto_cleanse(pinfield, sizeof(pinfield));
	crypto_cleanse(panfield, sizeof(panfield));

	return r;
}

int pinblock_encode_iso9564_format4_pinfield(
	const uint8_t* pin,
	size_t pin_len,
	uint8_t* pinfield
)
{
	int r;

	if (!pin || !pin_len || !pinfield) {
		return -1;
	}

	// Validate PIN length
	// See ISO 9564-1:2017 8.1
	// See ISO 9564-1:2017 9.1
	if (pin_len < PINBLOCK_PIN_LENGTH_MIN ||
		pin_len > PINBLOCK_PIN_LENGTH_MAX
	) {
		r = -2;
		goto error;
	}

	// Build PIN field (first 8 bytes)
	// See ISO 9564-1:2017 9.4.2.2.2
	r = pinblock_pack_pin(PINBLOCK_ISO9564_FORMAT_4, pin, pin_len, 0xA, pinfield);
	if (r) {
		r = -3;
		goto error;
	}

	// Build PIN field (last 8 bytes)
	// See ISO 9564-1:2017 9.4.2.2.2
	crypto_rand(pinfield + PINBLOCK128_SIZE / 2, PINBLOCK128_SIZE / 2);

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that PIN field is unusable on error
	crypto_rand(pinfield, PINBLOCK128_SIZE);
exit:
	return r;
}

int pinblock_encode_iso9564_format4_panfield(
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* panfield
)
{
	int r;
	bool padding_found = false;
	size_t pan_digit_count = 0;

	if (!pan || !pan_len || !panfield) {
		return -1;
	}

	// Validate PAN before encoding PAN field and determine the number of valid
	// PAN digits that should be encoded
	for (size_t pan_idx = 0; pan_len > 0; ++pan_idx){
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

		// Validate digit
		if (!padding_found) {
			if (digit >= 0xA && digit <= 0xE) {
				// Invalid PAN digit
				r = -2;
				goto error;
			}

			// First padding digit found
			if (digit == 0xF) {
				padding_found = true;
				continue;
			}

			// Valid PAN digit
			++pan_digit_count;

		} else {
			// Skip over trailing padding
			if (digit != 0xF) {
				// Invalid padding digit
				r = -3;
				goto error;
			}
		}
	}

	// Validate PAN length
	// ISO 9564-1:2017 does not specify minimum or maximum PAN lengths.
	// However, ISO 7812 specifies that PANs are 10 - 19 digits and the number
	// of available PAN digits may impact the PAN encoding. It is therefore
	// reasonable to reject invalid PAN lengths.
	if (pan_digit_count < 10) {
		r = -4;
		goto error;
	}
	if (pan_digit_count > 19) {
		r = -5;
		goto error;
	}

	// Build PAN field
	// See ISO 9564-1:2017 9.4.2.2.3
	memset(panfield, 0, PINBLOCK128_SIZE);

	if (pan_digit_count < 12) {
		// If PAN is less than 12 digits, M is zero
		// PAN digits will be right justified and left padded with zeros

		size_t panfield_idx = 12; // Start after M digit

		for (size_t i = 0; i < pan_digit_count; ++i) {
			uint8_t digit;
			size_t pan_idx = pan_digit_count - 1 - i; // Reverse order

			// Extract PAN digit
			if ((pan_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				digit = pan[pan_idx >> 1] >> 4;
			} else { // Odd digit index
				// Least significant nibble
				digit = pan[pan_idx >> 1] & 0xF;
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

		size_t panfield_idx = 1; // Start after M digit

		for (size_t pan_idx = 0; pan_idx < pan_digit_count; ++pan_idx) {
			uint8_t digit;

			// Extract PAN digit
			if ((pan_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				digit = pan[pan_idx >> 1] >> 4;
			} else { // Odd digit index
				// Least significant nibble
				digit = pan[pan_idx >> 1] & 0xF;
			}

			// Pack digit into PAN field
			// See ISO 9564-1:2017 9.4.2.2.3
			if ((panfield_idx & 0x1) == 0) { // Even digit index
				// Most significant nibble
				panfield[panfield_idx >> 1] = (digit << 4);
			} else { // Odd digit index
				// Least significant nibble
				panfield[panfield_idx >> 1] |= digit;
			}
			++panfield_idx;
		}

		// Populate M
		panfield[0] |= (pan_digit_count - 12) << 4;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that PAN field is unusable on error
	crypto_cleanse(panfield, PINBLOCK128_SIZE);
exit:
	return r;
}

int pinblock_decode_iso9564_format4_pinfield(
	const uint8_t* pinfield,
	size_t pinfield_len,
	uint8_t* pin,
	size_t* pin_len
)
{
	int r;

	if (!pinfield || !pin || !pin_len) {
		return -1;
	}
	*pin_len = 0;

	if (pinfield_len != PINBLOCK128_SIZE) {
		// Invalid PIN block size
		return 1;
	}

	// Decode PIN
	r = pinblock_unpack_pin(PINBLOCK_ISO9564_FORMAT_4, pinfield, pin, pin_len);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pin, PINBLOCK_PIN_LENGTH_MAX);
exit:
	return r;
}

int pinblock_get_format(const uint8_t* pinblock, size_t pinblock_len)
{
	uint8_t format;

	if (!pinblock || !pinblock_len) {
		return -1;
	}

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

	return -2;
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
