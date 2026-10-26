cmake_minimum_required(VERSION 3.16)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Debug, Release, RelWithDebInfo, or MinSizeRel" FORCE)
endif()
project(libparsock C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(APPLE AND EXISTS "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "OpenSSL 3 prefix" FORCE)
elseif(APPLE AND EXISTS "/usr/local/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3" CACHE PATH "OpenSSL 3 prefix" FORCE)
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

option(PARSOCK_ASAN "Build with AddressSanitizer" OFF)

add_library(parsock STATIC
    src/log.c
    src/frame.c
    src/crypto.c
    src/reassembly.c
    src/autoscale.c
    src/discover.c
    src/net.c
    src/tls.c
    src/options.c
    src/session.c
    src/drive.c
    src/standalone.c
)
target_include_directories(parsock
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(parsock PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_compile_options(parsock PRIVATE -Wall -Wextra -Werror)

if(PARSOCK_ASAN)
    target_compile_options(parsock PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(parsock PUBLIC -fsanitize=address,undefined)
endif()

find_program(OPENSSL_BIN openssl REQUIRED)

set(TEST_CERT ${CMAKE_CURRENT_BINARY_DIR}/cert.pem)
set(TEST_KEY ${CMAKE_CURRENT_BINARY_DIR}/key.pem)
add_custom_command(
    OUTPUT ${TEST_CERT} ${TEST_KEY}
    COMMAND ${OPENSSL_BIN} req -x509 -newkey rsa:2048
            -keyout ${TEST_KEY} -out ${TEST_CERT}
            -days 2 -nodes
            -subj "/CN=127.0.0.1"
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    VERBATIM
)
add_custom_target(parsock_test_certs DEPENDS ${TEST_CERT} ${TEST_KEY})

function(parsock_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE parsock)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_dependencies(${name} parsock_test_certs)
endfunction()

parsock_test(test_frame tests/test_frame.c)
parsock_test(test_crypto tests/test_crypto.c)
parsock_test(test_reassembly tests/test_reassembly.c)
parsock_test(test_autoscale tests/test_autoscale.c)
parsock_test(test_transfer tests/test_transfer.c)
parsock_test(test_embed tests/test_embed.c)
parsock_test(test_protect tests/test_protect.c)

enable_testing()
add_test(NAME frame COMMAND test_frame)
add_test(NAME crypto COMMAND test_crypto)
add_test(NAME reassembly COMMAND test_reassembly)
add_test(NAME autoscale COMMAND test_autoscale)
add_test(NAME transfer COMMAND test_transfer ${TEST_CERT} ${TEST_KEY})
add_test(NAME embed COMMAND test_embed ${TEST_CERT} ${TEST_KEY})
add_test(NAME protect COMMAND test_protect ${TEST_CERT} ${TEST_KEY})

add_executable(test_cxx tests/test_cxx.cpp)
target_link_libraries(test_cxx PRIVATE parsock)
target_compile_options(test_cxx PRIVATE -Wall -Wextra -Werror)
add_dependencies(test_cxx parsock_test_certs)
add_test(NAME cxx COMMAND test_cxx ${TEST_CERT} ${TEST_KEY})

add_executable(spt_http examples/spt_http.c)
target_link_libraries(spt_http PRIVATE parsock)
target_compile_options(spt_http PRIVATE -Wall -Wextra -Werror)

add_executable(spt_bulk examples/spt_bulk.c)
target_link_libraries(spt_bulk PRIVATE parsock)
target_compile_options(spt_bulk PRIVATE -Wall -Wextra -Werror)

add_executable(spt_bench examples/spt_bench.cpp)
target_link_libraries(spt_bench PRIVATE parsock)
target_compile_options(spt_bench PRIVATE -Wall -Wextra -Werror)
add_dependencies(spt_bench parsock_test_certs)
add_test(NAME bench COMMAND spt_bench self-test ${TEST_CERT} ${TEST_KEY})
set_tests_properties(transfer embed protect cxx bench PROPERTIES TIMEOUT 60)

install(TARGETS parsock ARCHIVE DESTINATION lib)
install(FILES include/parsock.h include/parsock.hpp include/spt_wire.h DESTINATION include)
