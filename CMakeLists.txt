##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

# NOTE: This is not intended to be a standalone project. It is intended to be
# an object library that can be added to other projects.

project(pinblock
	VERSION 0.1.0
	DESCRIPTION "OpenEMV PIN block implementation"
	HOMEPAGE_URL "https://github.com/openemv/pinblock"
	LANGUAGES C
)

# Parent scope must provide OpenEMV crypto libraries
if(NOT TARGET crypto_mem OR NOT TARGET crypto_rand)
	message(FATAL_ERROR "Parent project must provide crypto libraries")
endif()

add_library(pinblock OBJECT EXCLUDE_FROM_ALL)
target_sources(pinblock PRIVATE src/pinblock.c)
target_include_directories(pinblock INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)
target_link_libraries(pinblock PRIVATE crypto_mem crypto_rand)

# Configure various compilation properties
set_target_properties(
	pinblock
	PROPERTIES
		C_STANDARD 11
		C_EXTENSIONS OFF
		C_VISIBILITY_PRESET hidden
)
if(BUILD_SHARED_LIBS)
	set_target_properties(
		pinblock
		PROPERTIES
			POSITION_INDEPENDENT_CODE True
	)
endif()

# Only add tests if this is the top-level project
if(pinblock_IS_TOP_LEVEL)
	include(CTest)
	add_subdirectory(test)
endif()
