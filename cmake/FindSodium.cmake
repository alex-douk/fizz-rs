# FindSodium.cmake
# Finds the Sodium library (libsodium)

find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_SODIUM QUIET libsodium)
endif()

find_path(Sodium_INCLUDE_DIR
    NAMES sodium.h
    PATHS ${PC_SODIUM_INCLUDE_DIRS}
    PATH_SUFFIXES sodium
)

find_library(Sodium_LIBRARY
    NAMES sodium libsodium
    PATHS ${PC_SODIUM_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS Sodium_LIBRARY Sodium_INCLUDE_DIR
    VERSION_VAR PC_SODIUM_VERSION
)

if(Sodium_FOUND AND NOT TARGET Sodium::sodium)
    add_library(Sodium::sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${Sodium_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)
