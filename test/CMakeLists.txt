##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

if(BUILD_TESTING)
	add_executable(pinblock_format0_test pinblock_format0_test.c)
	target_link_libraries(pinblock_format0_test pinblock crypto_mem crypto_rand)
	add_test(pinblock_format0_test pinblock_format0_test)

	add_executable(pinblock_format1_test pinblock_format1_test.c)
	target_link_libraries(pinblock_format1_test pinblock crypto_mem crypto_rand)
	add_test(pinblock_format1_test pinblock_format1_test)

	add_executable(pinblock_format2_test pinblock_format2_test.c)
	target_link_libraries(pinblock_format2_test pinblock crypto_mem crypto_rand)
	add_test(pinblock_format2_test pinblock_format2_test)
endif()
