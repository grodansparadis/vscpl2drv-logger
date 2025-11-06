# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2025 Åke Hedman, the VSCP Project
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# VSCP_PATH - set to path to local vscp repository. Default is "../vscp". Set with
# -DVSCP_PATH="path"
#

cmake_minimum_required(VERSION 3.5)

# Parse version from header file first
function(parse_version_header version_file)
    if(EXISTS ${version_file})
        file(READ ${version_file} VERSION_HEADER_CONTENT)
        
        # Extract MAJOR_VERSION
        string(REGEX MATCH "#define[ \t]+VSCPL2DRV_LOGGER_MAJOR_VERSION[ \t]+([0-9]+)" 
               MAJOR_MATCH "${VERSION_HEADER_CONTENT}")
        if(MAJOR_MATCH)
            string(REGEX REPLACE "#define[ \t]+VSCPL2DRV_LOGGER_MAJOR_VERSION[ \t]+([0-9]+)" "\\1" 
                   PARSED_MAJOR_VERSION "${MAJOR_MATCH}")
            set(MAJOR_VERSION ${PARSED_MAJOR_VERSION} PARENT_SCOPE)
        endif()
        
        # Extract MINOR_VERSION
        string(REGEX MATCH "#define[ \t]+VSCPL2DRV_LOGGER_MINOR_VERSION[ \t]+([0-9]+)" 
               MINOR_MATCH "${VERSION_HEADER_CONTENT}")
        if(MINOR_MATCH)
            string(REGEX REPLACE "#define[ \t]+VSCPL2DRV_LOGGER_MINOR_VERSION[ \t]+([0-9]+)" "\\1" 
                   PARSED_MINOR_VERSION "${MINOR_MATCH}")
            set(MINOR_VERSION ${PARSED_MINOR_VERSION} PARENT_SCOPE)
        endif()
        
        # Extract RELEASE_VERSION (used as PATCH_VERSION)
        string(REGEX MATCH "#define[ \t]+VSCPL2DRV_LOGGER_RELEASE_VERSION[ \t]+([0-9]+)" 
               RELEASE_MATCH "${VERSION_HEADER_CONTENT}")
        if(RELEASE_MATCH)
            string(REGEX REPLACE "#define[ \t]+VSCPL2DRV_LOGGER_RELEASE_VERSION[ \t]+([0-9]+)" "\\1" 
                   PARSED_RELEASE_VERSION "${RELEASE_MATCH}")
            set(PATCH_VERSION ${PARSED_RELEASE_VERSION} PARENT_SCOPE)
        endif()
        
        # Extract BUILD_VERSION
        string(REGEX MATCH "#define[ \t]+VSCPL2DRV_LOGGER_BUILD_VERSION[ \t]+([0-9]+)" 
               BUILD_MATCH "${VERSION_HEADER_CONTENT}")
        if(BUILD_MATCH)
            string(REGEX REPLACE "#define[ \t]+BUILD_VERSION[ \t]+([0-9]+)" "\\1" 
                   PARSED_BUILD_VERSION "${BUILD_MATCH}")
            set(BUILD_VERSION ${PARSED_BUILD_VERSION} PARENT_SCOPE)
        endif()
        
        message(STATUS "Parsed version from ${version_file}: ${PARSED_MAJOR_VERSION}.${PARSED_MINOR_VERSION}.${PARSED_RELEASE_VERSION}.${PARSED_BUILD_VERSION}")
    else()
        message(WARNING "Version header file ${version_file} not found, using default values")
    endif()
endfunction()

# Parse version from header file
parse_version_header("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h")

project(vscpl2drv-logger VERSION ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION} LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# BUILD_VERSION from version.h (if not already set)
if(NOT DEFINED BUILD_VERSION)
    SET(BUILD_VERSION "0")
    message(STATUS "Using default BUILD_VERSION: ${BUILD_VERSION}")
endif()

message(STATUS "Final version: ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}.${BUILD_VERSION}")

# Force UTF-8 encoding for MSVC to fix spdlog/fmt Unicode issues
if(MSVC)
    add_compile_options(/utf-8)
    message(STATUS "Added /utf-8 flag for MSVC")
endif()

# Disable abi warnings (nlohmann)
if(WIN32)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
# Ensure WIN32 is defined for the preprocessor
add_definitions(-DWIN32)
add_definitions(-D_WIN32)
# Add UTF-8 support for spdlog/fmt
  add_compile_options(/utf-8)
else()
SET(GCC_VSCP_COMPILE_FLAGS "-Wno-psabi -D WITH_SYSTEMD")
endif()

# Prevent abi warnings in nlohmann
SET(GCC_VSCP_COMPILE_FLAGS "-Wno-psabi")
# Profiling
#SET(GCC_VSCP_LINK_FLAGS    "-lgcov")

SET(CPACK_PACKAGE_DESCRIPTION "VSCP driver for log functionality")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VSCP level II Driver for VSCP that export logging functionality")
SET(CPACK_PACKAGE_VENDOR "the VSCP Project")
SET(CPACK_PACKAGE_CONTACT "akhe@vscp.org")

if(NOT DEFINED APP_LOW_NAME)
  set(APP_LOW_NAME "vscpl2drv-logger")
endif()

if(NOT DEFINED APP_NAME)
  set(APP_NAME "VSCPL2DRV-LOGGER")
endif()

if(NOT DEFINED APP_URL)
  set(APP_URL "https://github.com/grodansparadis/vscpl2drv-logger")
endif()

if(NOT DEFINED APP_VERSION)
  set(APP_VERSION, "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
endif()

# Test application
add_subdirectory(testapp)

# Man build and install
if(NOT DEFINED WIN32)
  add_subdirectory(man)
endif()

option(USE_SSL "Use SSL" TRUE)

## --- C++11 build flags ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Build locations
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Default location for VSCP level II drivers
set(VSCP_LEVEL2_DRV_DIR /var/lib/vscp/drivers/level2/)

# Generate position-independent code (-fPIC on UNIX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- System Libraries ---
include(GNUInstallDirs)

if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-DWIN32_LEAN_AND_MEANS)
  add_definitions(-DOPENSSL_API_1_1)
  add_definitions(-D_POSIX_C_SOURCE)    
  add_definitions(-DVCPKG_TARGET_TRIPLET=x64-windows)
  add_definitions(-DMG_TLS=MG_TLS_OPENSSL)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
  set(LIBS_SYSTEM ws2_32)
elseif(UNIX)
  set(LIBS_SYSTEM c stdc++)
  add_definitions(-DMG_TLS=MG_TLS_OPENSSL)
  if(APPLE)
    # Suppress deprecation warnings for semaphore functions on macOS
    add_compile_options(-Wno-deprecated-declarations)
  endif()
endif()

#   ===========================  cpack  ===========================
IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
  INCLUDE(InstallRequiredSystemLibraries)

  IF(WIN32)
    SET(CPACK_SET_DESTDIR OFF)
  ELSE()
    SET(CPACK_SET_DESTDIR ON)
    SET(CPACK_PACKAGING_INSTALL_PREFIX "/var/lib/vscp/drivers")
  ENDIF()

  IF(WIN32)
    SET(CPACK_GENERATOR "NSIS" "ZIP")
  ELSE()
    SET(CPACK_GENERATOR "DEB" "RPM" "TGZ" "ZIP")
  ENDIF()
  
  set(CPACK_PACKAGE_NAME ${APP_LOW_NAME})
  set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY ${APP_NAME})


  SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
  SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
  SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
  #SET(CPACK_IGNORE_FILES "\\.psd$;/CVS/;/\\.svn/;/\\.git/;\\.swp$;/CMakeLists.txt.user;\\.#;/#;\\.tar.gz$;/CMakeFiles/;CMakeCache.txt;\\.qm$;/build/;\\.diff$;.DS_Store'")
  #set(CPACK_SOURCE_IGNORE_FILES ${CPACK_IGNORE_FILES})

  SET(CPACK_NSIS_INSTALLED_ICON_NAME "${APP_LOW_NAME}.ico")
  SET(CPACK_NSIS_HELP_LINK ${APP_URL})
  SET(CPACK_NSIS_URL_INFO_ABOUT ${APP_URL})

  IF(NOT DEFINED WIN32)
    SET(CPACK_DEBIAN_PACKAGE_DEPENDS " libexpat-dev, libssl-dev ")
    SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    SET(CPACK_DEBIAN_PACKAGE_SECTION "network")
    SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
  ENDIF()

  SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)

  # Configure file with custom definitions for NSIS.
  configure_file(
    ${PROJECT_SOURCE_DIR}/resources/nsis/NSIS.definitions.nsh.in
    ${CMAKE_CURRENT_BINARY_DIR}/resources/nsis/NSIS.definitions.nsh
  )

  # Load packaging facilities.
  INCLUDE(CPack)

ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")

# Disable abi warnings (nlohmann)
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_VSCP_COMPILE_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_VSCP_LINK_FLAGS}")

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# pthreads
set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#openssl
find_package(OpenSSL REQUIRED)

# Expat C library
if(WIN32)
find_package(expat CONFIG REQUIRED)
else()
include (FindEXPAT)
find_package(EXPAT REQUIRED)
include_directories(${EXPAT_INCLUDE_DIRS})
endif()

# Set sockettcp build flags
add_definitions(-DUSE_IPV6)
string(FIND "${OPENSSL_VERSION}" "1.1." SSL_VER_POS)
if(${SSL_VER_POS})
  add_definitions(-DOPENSSL_API_1_0)
else()
  add_definitions(-DOPENSSL_API_1_1)
endif()

set(RESOURCE_FILES
        README.md
        forms/index.html)

# Add files to library
add_library(vscpl2drv-logger
  ./src/vscpl2drv-logger.cpp
  ./common/log.cpp
  ./common/log.cpp
  ./third_party/Mustache/mustache.hpp
  ./third_party/spdlog/include/spdlog/spdlog.h
  ./third_party/vscp/src/vscp/common/vscp.h
  ./third_party/vscp/src/vscp/common/vscphelper.h
  ./third_party/vscp/src/vscp/common/vscphelper.cpp
)

if (WIN32)
    
  find_package(pthreads REQUIRED)
  find_path(PTHREAD_INCLUDE_DIR pthread.h)

  include_directories( PUBLIC src/
    ./third_party/vscp/src/vscp/common/  
    ./third_party/vscp/src/common
    ./third_party/json/include
    ./third_party/spdlog/include
    ./third_party/Mustache
    ./third_party/maddy/include
    ${PThreads4W_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LOCAL_WIN_INCLUDE}
    ${LOCAL_SYSLOG_INCLUDE} )
else()
  include_directories( PUBLIC src/
    ./third_party/vscp/src/vscp/common/  
    ./third_party/vscp/src/common
    ./third_party/json/include
    ./third_party/spdlog/include
    ./third_party/Mustache
    ./third_party/maddy/include
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LOCAL_SYSLOG_INCLUDE} )
 endif()   

if (WIN32)
  target_link_libraries(vscpl2drv-logger PRIVATE     
    PThreads4W::PThreads4W_CXXEXC
    OpenSSL::SSL 
    OpenSSL::Crypto
    OpenSSL::SSL OpenSSL::Crypto
    expat::expat
  )
        
else()
  target_link_libraries(vscpl2drv-logger PRIVATE     
    m
    dl
    Threads::Threads
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${EXPAT_LIBRARIES}
  )
endif()

# Install
if(WIN32)
  # Runtime files
  install(TARGETS vscpl2drv-logger
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  # Dependencies
  file(GLOB deps_files "${CMAKE_BINARY_DIR}/Release/*.dll")
  install(FILES ${deps_files} DESTINATION ${CMAKE_INSTALL_BINDIR})
  # LICENSE
  install(FILES "${CMAKE_BINARY_DIR}/../LICENSE" DESTINATION "${CMAKE_INSTALL_BINDIR}/..")
  # README
  install(FILES "${CMAKE_BINARY_DIR}/../README.md" DESTINATION "${CMAKE_INSTALL_BINDIR}/..")
else()
  install(TARGETS vscpl2drv-logger
          LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_}${VSCP_LEVEL2_DRV_DIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_MANDIR}            
          RESOURCE DESTINATION ${CMAKE_INSTALL_FULL_}/var/lib/vscp/vscpd) 
  install(FILES ${CMAKE_SOURCE_DIR}/resources/linux/v2logger.json
          DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/vscpl2drv-logger/")         
endif()
