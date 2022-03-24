# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT zigbee_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT zigbee_sources)

########################################################################
# Check for pygccxml
########################################################################
GR_PYTHON_CHECK_MODULE_RAW(
    "pygccxml"
    "import pygccxml"
    PYGCCXML_FOUND
    )

include(GrPybind)

########################################################################
# Python Bindings
########################################################################

list(APPEND zigbee_python_files
        packet_sink_scapy_python.cc
        preamble_prefixer_scapy_python.cc
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(zigbee
   ../../..
   gr::zigbee
   "${zigbee_python_files}")

# copy in bindings .so file for use in QA test module
add_custom_target(
  copy_bindings_for_tests ALL
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/*.so"
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/zigbee/
  DEPENDS zigbee_python)

install(TARGETS zigbee_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/zigbee COMPONENT pythonapi)
