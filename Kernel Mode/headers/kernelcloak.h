#pragma once

// KernelCloak - Header-only C++17 kernel-mode obfuscation library
// Include this single header to access all features.

// configuration and compiler macros
#include "kernelcloak/config.h"

// core primitives (no external dependencies)
#include "kernelcloak/core/types.h"
#include "kernelcloak/core/array.h"
#include "kernelcloak/core/memory.h"
#include "kernelcloak/core/sync.h"
#include "kernelcloak/core/random.h"
#include "kernelcloak/core/string_utils.h"

// cryptographic primitives (depends on core)
#include "kernelcloak/crypto/hash.h"
#include "kernelcloak/crypto/xor_cipher.h"
#include "kernelcloak/crypto/xtea.h"

// string obfuscation (depends on core + crypto)
#if KC_ENABLE_STRING_ENCRYPTION
#include "kernelcloak/strings/encrypted_string.h"
#include "kernelcloak/strings/encrypted_wstring.h"
#include "kernelcloak/strings/stack_string.h"
#include "kernelcloak/strings/layered_string.h"
#endif

// value and control flow obfuscation (depends on core)
#if KC_ENABLE_VALUE_OBFUSCATION
#include "kernelcloak/obfuscation/value.h"
#endif

#if KC_ENABLE_MBA
#include "kernelcloak/obfuscation/mba.h"
#include "kernelcloak/obfuscation/compare.h"
#endif

#if KC_ENABLE_BOOLEAN_OBFUSCATION
#include "kernelcloak/obfuscation/boolean.h"
#endif

#if KC_ENABLE_CONTROL_FLOW
#include "kernelcloak/obfuscation/control_flow.h"
#endif

#if KC_ENABLE_CFG_FLATTEN
#include "kernelcloak/obfuscation/cfg_flatten.h"
#include "kernelcloak/obfuscation/cfg_protect.h"
#endif

// security features (depends on core + crypto)
// import_hiding comes first - other security headers use it for dynamic resolution
#if KC_ENABLE_IMPORT_HIDING
#include "kernelcloak/security/import_hiding.h"
#endif

#if KC_ENABLE_ANTI_DEBUG
#include "kernelcloak/security/anti_debug.h"
#endif

#if KC_ENABLE_ANTI_VM
#include "kernelcloak/security/anti_vm.h"
#endif

#if KC_ENABLE_INTEGRITY
#include "kernelcloak/security/integrity.h"
#endif

#if KC_ENABLE_PE_ERASE
#include "kernelcloak/security/pe_erase.h"
#endif
