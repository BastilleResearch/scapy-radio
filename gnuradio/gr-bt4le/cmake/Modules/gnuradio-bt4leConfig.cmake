find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_BT4LE gnuradio-bt4le)

FIND_PATH(
    GR_BT4LE_INCLUDE_DIRS
    NAMES gnuradio/bt4le/api.h
    HINTS $ENV{BT4LE_DIR}/include
        ${PC_BT4LE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_BT4LE_LIBRARIES
    NAMES gnuradio-bt4le
    HINTS $ENV{BT4LE_DIR}/lib
        ${PC_BT4LE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-bt4leTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_BT4LE DEFAULT_MSG GR_BT4LE_LIBRARIES GR_BT4LE_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_BT4LE_LIBRARIES GR_BT4LE_INCLUDE_DIRS)
