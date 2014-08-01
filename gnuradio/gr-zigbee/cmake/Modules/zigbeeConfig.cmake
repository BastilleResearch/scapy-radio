INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_ZIGBEE zigbee)

FIND_PATH(
    ZIGBEE_INCLUDE_DIRS
    NAMES zigbee/api.h
    HINTS $ENV{ZIGBEE_DIR}/include
        ${PC_ZIGBEE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    ZIGBEE_LIBRARIES
    NAMES gnuradio-zigbee
    HINTS $ENV{ZIGBEE_DIR}/lib
        ${PC_ZIGBEE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ZIGBEE DEFAULT_MSG ZIGBEE_LIBRARIES ZIGBEE_INCLUDE_DIRS)
MARK_AS_ADVANCED(ZIGBEE_LIBRARIES ZIGBEE_INCLUDE_DIRS)

