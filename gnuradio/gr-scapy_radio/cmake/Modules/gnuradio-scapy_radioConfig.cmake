find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_SCAPY_RADIO gnuradio-scapy_radio)

FIND_PATH(
    GR_SCAPY_RADIO_INCLUDE_DIRS
    NAMES gnuradio/scapy_radio/api.h
    HINTS $ENV{SCAPY_RADIO_DIR}/include
        ${PC_SCAPY_RADIO_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_SCAPY_RADIO_LIBRARIES
    NAMES gnuradio-scapy_radio
    HINTS $ENV{SCAPY_RADIO_DIR}/lib
        ${PC_SCAPY_RADIO_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-scapy_radioTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_SCAPY_RADIO DEFAULT_MSG GR_SCAPY_RADIO_LIBRARIES GR_SCAPY_RADIO_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_SCAPY_RADIO_LIBRARIES GR_SCAPY_RADIO_INCLUDE_DIRS)
