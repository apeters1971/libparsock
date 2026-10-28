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

# libngtcp2_crypto_ossl is built against one OpenSSL. Prefer that prefix so
# the process does not load a second libssl. Homebrew's ngtcp2 formula
# currently links OpenSSL 4; otherwise stay on OpenSSL 3.
if(NOT DEFINED OPENSSL_ROOT_DIR)
    if(APPLE AND EXISTS "/opt/homebrew/opt/openssl@4/lib/libssl.dylib")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@4" CACHE PATH "OpenSSL prefix" FORCE)
    elseif(APPLE AND EXISTS "/opt/homebrew/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "OpenSSL prefix" FORCE)
    elseif(APPLE AND EXISTS "/usr/local/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3" CACHE PATH "OpenSSL prefix" FORCE)
    endif()
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

option(PARSOCK_ASAN "Build with AddressSanitizer" OFF)
option(PARSOCK_RDMA "Build the RDMA RC backend when librdmacm is available" ON)
set(PARSOCK_HAVE_RDMA OFF)
if(PARSOCK_RDMA)
    find_path(RDMA_INCLUDE_DIR rdma/rdma_cma.h)
    find_library(RDMA_CM_LIBRARY rdmacm)
    find_library(IBVERBS_LIBRARY ibverbs)
    if(RDMA_INCLUDE_DIR AND RDMA_CM_LIBRARY AND IBVERBS_LIBRARY)
        set(PARSOCK_HAVE_RDMA ON)
    endif()
endif()
if(PARSOCK_HAVE_RDMA)
    message(STATUS "libparsock RDMA backend: ON")
else()
    message(STATUS "libparsock RDMA backend: OFF")
endif()

option(PARSOCK_QUIC "Build the QUIC backend when libngtcp2 is available" ON)
set(PARSOCK_HAVE_QUIC OFF)
if(PARSOCK_QUIC)
    find_path(NGTCP2_INCLUDE_DIR ngtcp2/ngtcp2.h
              PATHS /opt/homebrew/include /usr/local/include)
    find_library(NGTCP2_LIBRARY ngtcp2
                 PATHS /opt/homebrew/lib /usr/local/lib)
    find_library(NGTCP2_CRYPTO_LIBRARY ngtcp2_crypto_ossl
                 PATHS /opt/homebrew/lib /usr/local/lib)
    if(NGTCP2_INCLUDE_DIR AND NGTCP2_LIBRARY AND NGTCP2_CRYPTO_LIBRARY)
        if(CMAKE_CROSSCOMPILING)
            set(PARSOCK_HAVE_QUIC ON)
        else()
            include(CheckCSourceRuns)
            set(_prev_req_inc ${CMAKE_REQUIRED_INCLUDES})
            set(_prev_req_lib ${CMAKE_REQUIRED_LIBRARIES})
            set(CMAKE_REQUIRED_INCLUDES ${NGTCP2_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
            set(CMAKE_REQUIRED_LIBRARIES ${NGTCP2_CRYPTO_LIBRARY} ${NGTCP2_LIBRARY} OpenSSL::SSL OpenSSL::Crypto)
            check_c_source_runs("
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 1;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return 1;
    ngtcp2_crypto_ossl_ctx *ossl = NULL;
    if (ngtcp2_crypto_ossl_ctx_new(&ossl, NULL) != 0) return 1;
    ngtcp2_crypto_ossl_ctx_set_ssl(ossl, ssl);
    if (ngtcp2_crypto_ossl_configure_client_session(ssl) != 0) return 1;
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ngtcp2_crypto_ossl_ctx_del(ossl);
    return 0;
}
" NGTCP2_CRYPTO_OSSL_COMPAT)
            set(CMAKE_REQUIRED_INCLUDES ${_prev_req_inc})
            set(CMAKE_REQUIRED_LIBRARIES ${_prev_req_lib})
            if(NGTCP2_CRYPTO_OSSL_COMPAT)
                set(PARSOCK_HAVE_QUIC ON)
            else()
                message(STATUS "libngtcp2_crypto_ossl is incompatible with selected OpenSSL; disabling QUIC")
            endif()
        endif()
    endif()
endif()
if(PARSOCK_HAVE_QUIC)
    message(STATUS "libparsock QUIC backend: ON")
else()
    message(STATUS "libparsock QUIC backend: OFF")
endif()

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
    src/quic.c
    src/rdma.c
    src/drive.c
    src/standalone.c
)
target_include_directories(parsock
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(parsock PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_compile_options(parsock PRIVATE -Wall -Wextra -Werror)
if(PARSOCK_HAVE_RDMA)
    target_compile_definitions(parsock PRIVATE PARSOCK_HAVE_RDMA=1)
    target_include_directories(parsock PRIVATE ${RDMA_INCLUDE_DIR})
    target_link_libraries(parsock PUBLIC ${RDMA_CM_LIBRARY} ${IBVERBS_LIBRARY})
endif()
if(PARSOCK_HAVE_QUIC)
    target_compile_definitions(parsock PRIVATE PARSOCK_HAVE_QUIC=1)
    target_include_directories(parsock PRIVATE ${NGTCP2_INCLUDE_DIR})
    target_link_libraries(parsock PUBLIC ${NGTCP2_LIBRARY} ${NGTCP2_CRYPTO_LIBRARY})
endif()

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
parsock_test(test_rdma tests/test_rdma.c)
parsock_test(test_quic tests/test_quic.c)
parsock_test(test_crypto tests/test_crypto.c)
parsock_test(test_reassembly tests/test_reassembly.c)
parsock_test(test_autoscale tests/test_autoscale.c)
parsock_test(test_transfer tests/test_transfer.c)
parsock_test(test_embed tests/test_embed.c)
parsock_test(test_protect tests/test_protect.c)
parsock_test(test_gpu tests/test_gpu.c)

enable_testing()
add_test(NAME frame COMMAND test_frame)
add_test(NAME rdma COMMAND test_rdma)
add_test(NAME gpu COMMAND test_gpu)
add_test(NAME quic COMMAND test_quic ${TEST_CERT} ${TEST_KEY})
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
set_tests_properties(transfer embed protect cxx bench quic PROPERTIES TIMEOUT 60)

install(TARGETS parsock ARCHIVE DESTINATION lib)
install(FILES include/parsock.h include/parsock.hpp include/spt_wire.h DESTINATION include)
