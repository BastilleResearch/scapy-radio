find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_ZWAVE gnuradio-Zwave)

FIND_PATH(
    GR_ZWAVE_INCLUDE_DIRS
    NAMES gnuradio/Zwave/api.h
    HINTS $ENV{ZWAVE_DIR}/include
        ${PC_ZWAVE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_ZWAVE_LIBRARIES
    NAMES gnuradio-Zwave
    HINTS $ENV{ZWAVE_DIR}/lib
        ${PC_ZWAVE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-ZwaveTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_ZWAVE DEFAULT_MSG GR_ZWAVE_LIBRARIES GR_ZWAVE_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_ZWAVE_LIBRARIES GR_ZWAVE_INCLUDE_DIRS)
