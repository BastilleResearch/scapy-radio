INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_SCAPY_RADIO scapy_radio)

FIND_PATH(
    SCAPY_RADIO_INCLUDE_DIRS
    NAMES scapy_radio/api.h
    HINTS $ENV{SCAPY_RADIO_DIR}/include
        ${PC_SCAPY_RADIO_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    SCAPY_RADIO_LIBRARIES
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

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SCAPY_RADIO DEFAULT_MSG SCAPY_RADIO_LIBRARIES SCAPY_RADIO_INCLUDE_DIRS)
MARK_AS_ADVANCED(SCAPY_RADIO_LIBRARIES SCAPY_RADIO_INCLUDE_DIRS)

