# dependencies.cmake
#
# Third-party sources, fetched at configure time with FetchContent. They used
# to be git submodules in third-party/; each is pinned to the same commit.
# Every download is checked against its SHA256.
#
# To use a local checkout instead, set FETCHCONTENT_SOURCE_DIR_<NAME>, for
# example -DFETCHCONTENT_SOURCE_DIR_TP_SPDLOG=/path/to/spdlog.
# FETCHCONTENT_FULLY_DISCONNECTED=ON reuses downloaded sources offline.
#
# Sets:
#   THIRD_PARTY_SPDLOG_DIR             gabime/spdlog
#   THIRD_PARTY_MADDY_DIR              progsource/maddy
#   THIRD_PARTY_JSON_DIR               nlohmann/json
#   THIRD_PARTY_VSCP_DIR               grodansparadis/vscp
#   THIRD_PARTY_CRYPTO_ALGORITHMS_DIR  B-Con/crypto-algorithms
#   THIRD_PARTY_MUSTACHE_DIR           kainjow/Mustache
#

include_guard(GLOBAL)
include(FetchContent)

set(_tp_options)
if(NOT CMAKE_VERSION VERSION_LESS "3.18")
    # Populate the sources only; the projects are not added to the build.
    list(APPEND _tp_options SOURCE_SUBDIR "__sources_only__")
endif()
if(NOT CMAKE_VERSION VERSION_LESS "3.24")
    list(APPEND _tp_options DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endif()

# gabime/spdlog @ 79524ddd08a4ec981b7fea76afd08ee05f83755d
FetchContent_Declare(
    tp_spdlog
    URL https://codeload.github.com/gabime/spdlog/tar.gz/79524ddd08a4ec981b7fea76afd08ee05f83755d
    URL_HASH SHA256=c6dee844e35a54cc80e3ab76aae2310763e0b49c7397549dfa4d4657d9737138
    ${_tp_options}
)
# progsource/maddy @ 07dde0c63098c347e15c9e5559078b96c6cd3450
FetchContent_Declare(
    tp_maddy
    URL https://codeload.github.com/progsource/maddy/tar.gz/07dde0c63098c347e15c9e5559078b96c6cd3450
    URL_HASH SHA256=e22f2e40298e292f94c1b89929eebf09a54e1d73e2fcbe1deb89a7a0243f500f
    ${_tp_options}
)
# nlohmann/json @ af524ab666359f09a16bca1a41543a9a3a941251
FetchContent_Declare(
    tp_json
    URL https://codeload.github.com/nlohmann/json/tar.gz/af524ab666359f09a16bca1a41543a9a3a941251
    URL_HASH SHA256=d3a3bdba8f0300e5e4d3207e391ac6df15ba52b2f318679f3e0217b3310ad154
    ${_tp_options}
)
# grodansparadis/vscp @ 72968b7592dd1bfd8778afcfc7ddc2871616f662
FetchContent_Declare(
    tp_vscp
    URL https://codeload.github.com/grodansparadis/vscp/tar.gz/72968b7592dd1bfd8778afcfc7ddc2871616f662
    URL_HASH SHA256=5670d77547539bd4c151221a87c8a3cefea3f607812ab4ba5fd2308e1d529ac8
    ${_tp_options}
)
# B-Con/crypto-algorithms @ cfbde48414baacf51fc7c74f275190881f037d32
FetchContent_Declare(
    tp_crypto_algorithms
    URL https://codeload.github.com/B-Con/crypto-algorithms/tar.gz/cfbde48414baacf51fc7c74f275190881f037d32
    URL_HASH SHA256=525d7b38eb549e52b21f6fc5e21362b912d66912aa458a5e4819f9427fc8f477
    ${_tp_options}
)
# kainjow/Mustache @ 3f654942a70c46a775070d7a09ca7acfa3e205b7
FetchContent_Declare(
    tp_mustache
    URL https://codeload.github.com/kainjow/Mustache/tar.gz/3f654942a70c46a775070d7a09ca7acfa3e205b7
    URL_HASH SHA256=959b8fcaecc14fc0b6243c078a39fd13dab107dcda086ed2ca90e1a486269a36
    ${_tp_options}
)

set(_tp_names tp_spdlog tp_maddy tp_json tp_vscp tp_crypto_algorithms tp_mustache)
if(CMAKE_VERSION VERSION_LESS "3.18")
    foreach(_tp IN LISTS _tp_names)
        FetchContent_GetProperties(${_tp})
        if(NOT ${_tp}_POPULATED)
            FetchContent_Populate(${_tp})
        endif()
    endforeach()
else()
    FetchContent_MakeAvailable(${_tp_names})
endif()

set(THIRD_PARTY_SPDLOG_DIR "${tp_spdlog_SOURCE_DIR}")
set(THIRD_PARTY_MADDY_DIR "${tp_maddy_SOURCE_DIR}")
set(THIRD_PARTY_JSON_DIR "${tp_json_SOURCE_DIR}")
set(THIRD_PARTY_VSCP_DIR "${tp_vscp_SOURCE_DIR}")
set(THIRD_PARTY_CRYPTO_ALGORITHMS_DIR "${tp_crypto_algorithms_SOURCE_DIR}")
set(THIRD_PARTY_MUSTACHE_DIR "${tp_mustache_SOURCE_DIR}")
