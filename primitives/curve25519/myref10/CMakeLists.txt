cmake_minimum_required(VERSION 3.20)
project(myref10 C)

set(CMAKE_C_STANDARD 11)
add_compile_options(-Wall -Wextra -pedantic -Wno-unused-function)

# Add directories for extra cmake files, e.g. to find NTK and other libraries
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(sodium)
# define the following variables (see ./cmake/FindSodium.make)
#   sodium_FOUND
#   sodium_INCLUDE_DIR
#   sodium_LIBRARY_DEBUG
#   sodium_LIBRARY_RELEASE

include_directories(.)

# TODO FIXME: copy pasted the `-D` flags from `V=1 make` in a different libsodium
# HIGHLY non-portable!!
add_compile_options(-DPACKAGE_URL="https://libsodium.org" -DPACKAGE="libsodium" -DVERSION="1.0.18" -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DHAVE_WCHAR_H=1 -DSTDC_HEADERS=1 -D_ALL_SOURCE=1 -D_DARWIN_C_SOURCE=1 -D_GNU_SOURCE=1 -D_HPUX_ALT_XOPEN_SOCKET_API=1 -D_NETBSD_SOURCE=1 -D_OPENBSD_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D__STDC_WANT_IEC_60559_ATTRIBS_EXT__=1 -D__STDC_WANT_IEC_60559_BFP_EXT__=1 -D__STDC_WANT_IEC_60559_DFP_EXT__=1 -D__STDC_WANT_IEC_60559_FUNCS_EXT__=1 -D__STDC_WANT_IEC_60559_TYPES_EXT__=1 -D__STDC_WANT_LIB_EXT2__=1 -D__STDC_WANT_MATH_SPEC_FUNCS__=1 -D_TANDEM_SOURCE=1 -D__EXTENSIONS__=1 -DHAVE_PTHREAD_PRIO_INHERIT=1 -DHAVE_PTHREAD=1 -DHAVE_C_VARARRAYS=1 -DHAVE_CATCHABLE_SEGV=1 -DHAVE_CATCHABLE_ABRT=1 -DTLS=_Thread_local -DHAVE_DLFCN_H=1 -DLT_OBJDIR=".libs/" -DHAVE_MMINTRIN_H=1 -DHAVE_EMMINTRIN_H=1 -DHAVE_PMMINTRIN_H=1 -DHAVE_TMMINTRIN_H=1 -DHAVE_SMMINTRIN_H=1 -DHAVE_AVXINTRIN_H=1 -DHAVE_AVX2INTRIN_H=1 -DHAVE_AVX512FINTRIN_H=1 -DHAVE_WMMINTRIN_H=1 -DHAVE_RDRAND=1 -DHAVE_SYS_MMAN_H=1 -DHAVE_SYS_RANDOM_H=1 -DNATIVE_LITTLE_ENDIAN=1 -DHAVE_INLINE_ASM=1 -DHAVE_AMD64_ASM=1 -DHAVE_AVX_ASM=1 -DHAVE_TI_MODE=1 -DHAVE_CPUID=1 -DASM_HIDE_SYMBOL=.private_extern -DHAVE_WEAK_SYMBOLS=1 -DCPU_UNALIGNED_ACCESS=1 -DHAVE_ATOMIC_OPS=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_BUF=1 -DHAVE_MMAP=1 -DHAVE_MLOCK=1 -DHAVE_MADVISE=1 -DHAVE_MPROTECT=1 -DHAVE_GETENTROPY=1 -DHAVE_GETPID=1 -DHAVE_POSIX_MEMALIGN=1 -DHAVE_NANOSLEEP=1 -DHAVE_MEMSET_S=1 -DCONFIGURED=1)

add_library(myref10
        myref10.c
        myref10.h myref10.c myref10.h
        private/chacha20_ietf_ext.h
        private/common.h
        private/ed25519_ref10.h
        private/ed25519_ref10_fe_25_5.h
        private/ed25519_ref10_fe_51.h
        private/implementations.h
        private/mutex.h
        private/sse2_64_32.h
        ed25519_ref10.c
        ref10/fe_51/base.h
        ref10/fe_51/base2.h
        ref10/fe_51/constants.h
        ref10/fe_51/fe.h
        ref10/fe_25_5/base.h
        ref10/fe_25_5/base2.h
        ref10/fe_25_5/constants.h
        ref10/fe_25_5/fe.h)

target_include_directories(myref10 PUBLIC
        ${sodium_INCLUDE_DIR}
        )

target_link_libraries(myref10 PUBLIC
        ${sodium_LIBRARY_RELEASE}
        )

add_executable(main
        main/main.c)

target_link_libraries(main PRIVATE myref10)
