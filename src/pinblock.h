/**
 * @file pinblock.h
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

#ifndef PINBLOCK_H
#define PINBLOCK_H

#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>

__BEGIN_DECLS

#define PINBLOCK_SIZE (8) ///< PIN block size (in bytes) for ISO 9564-1:2017 format 0, 1, 2, 3
#define PINBLOCK128_SIZE (16) ///< PIN block size (in bytes) for ISO 9564-1:2017 format 4

/**
 * PIN block formats
 * @remark See ISO 9564-1:2017 9.3
 */
enum pinblock_format_t {
	PINBLOCK_ISO9564_FORMAT_0 = 0, ///< ISO 9564-1:2017 format 0
	PINBLOCK_ISO9564_FORMAT_1 = 1, ///< ISO 9564-1:2017 format 1
	PINBLOCK_ISO9564_FORMAT_2 = 2, ///< ISO 9564-1:2017 format 2
	PINBLOCK_ISO9564_FORMAT_3 = 3, ///< ISO 9564-1:2017 format 3
	PINBLOCK_ISO9564_FORMAT_4 = 4, ///< ISO 9564-1:2017 format 4
};

/**
 * Encode PIN block in accordance with ISO 9564-1:2017 PIN block format 0
 *
 * @param pin PIN buffer containing one PIN digit value per byte
 * @param pin_len Length of PIN
 * @param pan PAN buffer in compressed numeric format (EMV format "cn";
 *            nibble-per-digit; left justified; padded with trailing 0xF
 *            nibbles). This is the same format as EMV field @c 5A which
 *            typically contains the application PAN.
 * @param pan_len Length of PAN buffer in bytes
 * @param pinblock PIN block output of length @ref PINBLOCK_SIZE
 * @return Zero for success. Less than zero for error.
 */
int pinblock_encode_iso9564_format0(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinblock
);

/**
 * Decode PIN block in accordance with ISO 9564-1:2017 PIN block format 0
 *
 * @param pinblock PIN block
 * @param pinblock_len Length of PIN block in bytes
 * @param pan PAN buffer in compressed numeric format (EMV format "cn";
 *            nibble-per-digit; left justified; padded with trailing 0xF
 *            nibbles). This is the same format as EMV field @c 5A which
 *            typically contains the application PAN.
 * @param pan_len Length of PAN buffer in bytes
 * @param pin PIN buffer output of maximum 12 bytes/digits
 * @param pin_len Length of PIN buffer output
 * @return Zero for success. Less than zero for error.
 *         Greater than zero for invalid/unsupported PIN block format.
 */
int pinblock_decode_iso9564_format0(
	const uint8_t* pinblock,
	size_t pinblock_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pin,
	size_t* pin_len
);

/**
 * Encode PIN block in accordance with ISO 9564-1:2017 PIN block format 1
 *
 * @param pin PIN buffer containing one PIN digit value per byte
 * @param pin_len Length of PIN
 * @param nonce Unique padding field. This field must be unique for every
 *              occurance of the PIN block and may for example be the
 *              transaction sequence number (EMV field @c 9F41), time stamp,
 *              random data, or similar. Use NULL for random padding
 *              (recommended).
 * @param nonce_len Length of unique padding field. Must be at least
 *                  <tt>PINBLOCK_SIZE - 1 - (pin_len / 2)</tt>. Use zero for
 *                  random padding.
 * @param pinblock PIN block output of length @ref PINBLOCK_SIZE
 * @return Zero for success. Less than zero for error.
 */
int pinblock_encode_iso9564_format1(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* nonce,
	size_t nonce_len,
	uint8_t* pinblock
);

/**
 * Decode PIN block in accordance with ISO 9564-1:2017 PIN block format 1
 *
 * @param pinblock PIN block
 * @param pinblock_len Length of PIN block in bytes
 * @param pin PIN buffer output of maximum 12 bytes/digits
 * @param pin_len Length of PIN buffer output
 * @return Zero for success. Less than zero for error.
 *         Greater than zero for invalid/unsupported PIN block format.
 */
int pinblock_decode_iso9564_format1(
	const uint8_t* pinblock,
	size_t pinblock_len,
	uint8_t* pin,
	size_t* pin_len
);

/**
 * Encode PIN block in accordance with ISO 9564-1:2017 PIN block format 2
 *
 * @param pin PIN buffer containing one PIN digit value per byte
 * @param pin_len Length of PIN
 * @param pinblock PIN block output of length @ref PINBLOCK_SIZE
 * @return Zero for success. Less than zero for error.
 */
int pinblock_encode_iso9564_format2(
	const uint8_t* pin,
	size_t pin_len,
	uint8_t* pinblock
);

/**
 * Decode PIN block in accordance with ISO 9564-1:2017 PIN block format 2
 *
 * @param pinblock PIN block
 * @param pinblock_len Length of PIN block in bytes
 * @param pin PIN buffer output of maximum 12 bytes/digits
 * @param pin_len Length of PIN buffer output
 * @return Zero for success. Less than zero for error.
 *         Greater than zero for invalid/unsupported PIN block format.
 */
int pinblock_decode_iso9564_format2(
	const uint8_t* pinblock,
	size_t pinblock_len,
	uint8_t* pin,
	size_t* pin_len
);

/**
 * Encode PIN block in accordance with ISO 9564-1:2017 PIN block format 3
 *
 * @param pin PIN buffer containing one PIN digit value per byte
 * @param pin_len Length of PIN
 * @param pan PAN buffer in compressed numeric format (EMV format "cn";
 *            nibble-per-digit; left justified; padded with trailing 0xF
 *            nibbles). This is the same format as EMV field @c 5A which
 *            typically contains the application PAN.
 * @param pan_len Length of PAN buffer in bytes
 * @param pinblock PIN block output of length @ref PINBLOCK_SIZE
 * @return Zero for success. Less than zero for error.
 */
int pinblock_encode_iso9564_format3(
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinblock
);

/**
 * Decode PIN block in accordance with ISO 9564-1:2017 PIN block format 3
 *
 * @param pinblock PIN block
 * @param pinblock_len Length of PIN block in bytes
 * @param pan PAN buffer in compressed numeric format (EMV format "cn";
 *            nibble-per-digit; left justified; padded with trailing 0xF
 *            nibbles). This is the same format as EMV field @c 5A which
 *            typically contains the application PAN.
 * @param pan_len Length of PAN buffer in bytes
 * @param pin PIN buffer output of maximum 12 bytes/digits
 * @param pin_len Length of PIN buffer output
 * @return Zero for success. Less than zero for error.
 *         Greater than zero for invalid/unsupported PIN block format.
 */
int pinblock_decode_iso9564_format3(
	const uint8_t* pinblock,
	size_t pinblock_len,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pin,
	size_t* pin_len
);

/**
 * Encode PIN field in accordance with ISO 9564-1:2017 PIN block format 4
 *
 * @note It is the caller's responsibility to encipher and combine the PIN
 *       field and PAN field in accordance with ISO 9564-1:2017 9.4.2.3
 *
 * @param pin PIN buffer containing one PIN digit value per byte
 * @param pin_len Length of PIN
 * @param pinfield PIN field output of length @ref PINBLOCK128_SIZE
 * @return Zero for success. Less than zero for error.
 */
int pinblock_encode_iso9564_format4_pinfield(
	const uint8_t* pin,
	size_t pin_len,
	uint8_t* pinfield
);

/**
 * Encode PAN field in accordance with ISO 9564-1:2017 PIN block format 4
 *
 * @note It is the caller's responsibility to encipher and combine the PIN
 *       field and PAN field in accordance with ISO 9564-1:2017 9.4.2.3
 *
 * @param pan PAN buffer in compressed numeric format (EMV format "cn";
 *            nibble-per-digit; left justified; padded with trailing 0xF
 *            nibbles). This is the same format as EMV field @c 5A which
 *            typically contains the application PAN.
 * @param pan_len Length of PAN buffer in bytes
 * @param panfield PAN field output of length @ref PINBLOCK128_SIZE
 * @return Zero for success. Less than zero for error.
 */
int pinblock_encode_iso9564_format4_panfield(
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* panfield
);

/**
 * Decode PIN field in accordance with ISO 9564-1:2017 PIN block format 4
 *
 * @note It is the caller's responsibility to decipher and separate the PIN
 *       field and PAN field in accordance with ISO 9564-1:2017 9.4.2.4
 *
 * @param pinfield PIN field
 * @param pinfield_len Length of PIN field in bytes
 * @param pin PIN buffer output of maximum 12 bytes/digits
 * @param pin_len Length of PIN buffer output
 * @return Zero for success. Less than zero for error.
 *         Greater than zero for invalid/unsupported PIN block format.
 */
int pinblock_decode_iso9564_format4_pinfield(
	const uint8_t* pinfield,
	size_t pinfield_len,
	uint8_t* pin,
	size_t* pin_len
);

/**
 * Retrieve PIN block format
 *
 * @param pinblock PIN block
 * @param pinblock_len Length of PIN block in bytes
 * @return Zero or greater for PIN block format. See @ref pinblock_format_t.
 *         Less than zero for error.
 */
int pinblock_get_format(const uint8_t* pinblock, size_t pinblock_len);

/**
 * Decode PIN block in accordance with ISO 9564-1:2017
 *
 * @param pinblock PIN block
 * @param pinblock_len Length of PIN block in bytes
 * @param other Secondary field that may be relevant for PIN block decoding.
 *              For ISO 9564-1:2017 PIN block format 0 and format 3, this will
 *              be the PAN in compressed numeric format (EMV format "cn").
 *              For ISO 9564-1:2017 PIN block format 1, format 2 and format 4,
 *              this is ignored.
 * @param other_len Length of @p other in bytes
 * @param format PIN block format output. See @ref pinblock_format_t.
 * @param pin PIN buffer output of maximum 12 bytes/digits
 * @param pin_len Length of PIN buffer output
 * @return Zero for success. Less than zero for error.
 *         Greater than zero for invalid/unsupported PIN block format.
 */
int pinblock_decode(
	const uint8_t* pinblock,
	size_t pinblock_len,
	const uint8_t* other,
	size_t other_len,
	unsigned int* format,
	uint8_t* pin,
	size_t* pin_len
);

__END_DECLS

#endif
