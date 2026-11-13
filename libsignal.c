// libsignal-protocol-c in one unit; statics and macros shared by two files are renamed or undefined.
#if defined(_MSC_VER) && !defined(_WINDOWS)
#define _WINDOWS 1
#endif
#ifdef _MSC_VER
#define _CRT_NONSTDC_NO_WARNINGS
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WINDOWS
#include <basetsd.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(push, 1)
#pragma warning(disable: 4005 4098 4146 4163 4305 4311 4701 4702)
#endif
#ifdef __clang__
#pragma clang diagnostic ignored "-Wignored-attributes"
#pragma clang diagnostic ignored "-Wmacro-redefined"
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wunterminated-string-initialization"
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
#endif

// The upb files fill upb's structs by position: they must come from the generator of the protobuf built with them
#include "src/google/protobuf/runtime_version.h"
#if PROTOBUF_VERSION != 7036002
#error "Regenerate libsignal-protocol-c's upb files for this protobuf (bte's doc/Submodules.md, libsignal-protocol-c)"
#endif
#include "upb/generated_code_support.h"

#include "src/FingerprintProtocol.upb_minitable.c"
#include "src/LocalStorageProtocol.upb_minitable.c"
#include "src/WhisperTextProtocol.upb_minitable.c"

#include "src/vpool.c"
#include "src/signal_protocol.c"
#undef MIN
#include "src/curve.c"
#include "src/hkdf.c"
#undef HASH_OUTPUT_SIZE
#undef MIN
#undef MAX
#include "src/ratchet.c"
#undef HASH_OUTPUT_SIZE
#include "src/protocol.c"
#include "src/session_state.c"
#undef MAX_MESSAGE_KEYS
#include "src/session_record.c"
#include "src/session_pre_key.c"
#include "src/session_builder.c"
#include "src/session_cipher.c"
#include "src/key_helper.c"
#include "src/sender_key.c"
#undef HASH_OUTPUT_SIZE
#include "src/sender_key_state.c"
#undef MAX_MESSAGE_KEYS
#include "src/sender_key_record.c"
#include "src/group_session_builder.c"
#include "src/group_cipher.c"
#include "src/fingerprint.c"
#undef MAX
#include "src/device_consistency.c"

// glibc's math.h declares an fmul of its own
#define fmul donna_fmul
#include "src/curve25519/curve25519-donna.c"
#undef fmul
#undef inline

#include "src/curve25519/ed25519/fe_0.c"
#include "src/curve25519/ed25519/fe_1.c"
#include "src/curve25519/ed25519/fe_add.c"
#include "src/curve25519/ed25519/fe_cmov.c"
#include "src/curve25519/ed25519/fe_copy.c"
#define load_3 fe_frombytes_load_3
#define load_4 fe_frombytes_load_4
#include "src/curve25519/ed25519/fe_frombytes.c"
#undef load_3
#undef load_4
#include "src/curve25519/ed25519/fe_invert.c"
#include "src/curve25519/ed25519/fe_isnegative.c"
#include "src/curve25519/ed25519/fe_isnonzero.c"
#include "src/curve25519/ed25519/fe_mul.c"
#include "src/curve25519/ed25519/fe_neg.c"
#include "src/curve25519/ed25519/fe_pow22523.c"
#include "src/curve25519/ed25519/fe_sq.c"
#include "src/curve25519/ed25519/fe_sq2.c"
#include "src/curve25519/ed25519/fe_sub.c"
#include "src/curve25519/ed25519/fe_tobytes.c"
#include "src/curve25519/ed25519/ge_add.c"
#include "src/curve25519/ed25519/ge_double_scalarmult.c"
#include "src/curve25519/ed25519/ge_frombytes.c"
#include "src/curve25519/ed25519/ge_madd.c"
#include "src/curve25519/ed25519/ge_msub.c"
#include "src/curve25519/ed25519/ge_p1p1_to_p2.c"
#include "src/curve25519/ed25519/ge_p1p1_to_p3.c"
#include "src/curve25519/ed25519/ge_p2_0.c"
#include "src/curve25519/ed25519/ge_p2_dbl.c"
#include "src/curve25519/ed25519/ge_p3_0.c"
#include "src/curve25519/ed25519/ge_p3_dbl.c"
#include "src/curve25519/ed25519/ge_p3_to_cached.c"
#include "src/curve25519/ed25519/ge_p3_to_p2.c"
#include "src/curve25519/ed25519/ge_p3_tobytes.c"
#include "src/curve25519/ed25519/ge_precomp_0.c"
#define equal ge_scalarmult_base_equal
#define negative ge_scalarmult_base_negative
#define cmov ge_scalarmult_base_cmov
#define select ge_scalarmult_base_select
#include "src/curve25519/ed25519/ge_scalarmult_base.c"
#undef equal
#undef negative
#undef cmov
#undef select
#include "src/curve25519/ed25519/ge_sub.c"
#include "src/curve25519/ed25519/ge_tobytes.c"
#include "src/curve25519/ed25519/open.c"
#define load_3 sc_muladd_load_3
#define load_4 sc_muladd_load_4
#include "src/curve25519/ed25519/sc_muladd.c"
#undef load_3
#undef load_4
#define load_3 sc_reduce_load_3
#define load_4 sc_reduce_load_4
#include "src/curve25519/ed25519/sc_reduce.c"
#undef load_3
#undef load_4
#include "src/curve25519/ed25519/sign.c"

#include "src/curve25519/ed25519/additions/compare.c"
#undef F
#include "src/curve25519/ed25519/additions/curve_sigs.c"
#include "src/curve25519/ed25519/additions/elligator.c"
#include "src/curve25519/ed25519/additions/fe_isequal.c"
#include "src/curve25519/ed25519/additions/fe_isreduced.c"
// fe_mont_rhs.c leaves out the const its declaration in crypto_additions.h has; GCC and clang refuse the mismatch
#define fe_mont_rhs fe_mont_rhs_without_const
#include "src/curve25519/ed25519/additions/fe_mont_rhs.c"
#undef fe_mont_rhs
void fe_mont_rhs(fe v2, const fe u)
{
    fe_mont_rhs_without_const(v2, (crypto_int32*)u);
}
#include "src/curve25519/ed25519/additions/fe_montx_to_edy.c"
#include "src/curve25519/ed25519/additions/fe_sqrt.c"
#include "src/curve25519/ed25519/additions/ge_isneutral.c"
#include "src/curve25519/ed25519/additions/ge_montx_to_p3.c"
#include "src/curve25519/ed25519/additions/ge_neg.c"
#include "src/curve25519/ed25519/additions/ge_p3_to_montx.c"
#define equal ge_scalarmult_equal
#define negative ge_scalarmult_negative
#define cmov ge_scalarmult_cmov
#define select ge_scalarmult_select
#include "src/curve25519/ed25519/additions/ge_scalarmult.c"
#undef equal
#undef negative
#undef cmov
#undef select
#include "src/curve25519/ed25519/additions/ge_scalarmult_cofactor.c"
#include "src/curve25519/ed25519/additions/keygen.c"
#include "src/curve25519/ed25519/additions/open_modified.c"
#include "src/curve25519/ed25519/additions/sc_clamp.c"
#include "src/curve25519/ed25519/additions/sc_cmov.c"
#include "src/curve25519/ed25519/additions/sc_neg.c"
#include "src/curve25519/ed25519/additions/sign_modified.c"
#include "src/curve25519/ed25519/additions/utility.c"
#include "src/curve25519/ed25519/additions/xeddsa.c"
#include "src/curve25519/ed25519/additions/zeroize.c"
#include "src/curve25519/ed25519/additions/generalized/ge_p3_add.c"
#include "src/curve25519/ed25519/additions/generalized/gen_eddsa.c"
#include "src/curve25519/ed25519/additions/generalized/gen_labelset.c"
#include "src/curve25519/ed25519/additions/generalized/gen_veddsa.c"
#include "src/curve25519/ed25519/additions/generalized/gen_x.c"
#include "src/curve25519/ed25519/additions/generalized/point_isreduced.c"
#include "src/curve25519/ed25519/additions/generalized/sc_isreduced.c"

#include "src/curve25519/ed25519/nacl_sha512/blocks.c"
#undef F
#undef M
#undef EXPAND
#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef SHR
#undef ROTR
#define uint64 nacl_sha512_hash_uint64
#include "src/curve25519/ed25519/nacl_sha512/hash.c"
#undef uint64
#undef blocks

#include "src/curve25519/ed25519/tests/internal_fast_tests.c"
