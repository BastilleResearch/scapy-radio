find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_ZIGBEE gnuradio-zigbee)

FIND_PATH(
    GR_ZIGBEE_INCLUDE_DIRS
    NAMES gnuradio/zigbee/api.h
    HINTS $ENV{ZIGBEE_DIR}/include
        ${PC_ZIGBEE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_ZIGBEE_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-zigbeeTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_ZIGBEE DEFAULT_MSG GR_ZIGBEE_LIBRARIES GR_ZIGBEE_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_ZIGBEE_LIBRARIES GR_ZIGBEE_INCLUDE_DIRS)
