#!/usr/bin/env python3
"""
qc_inspect.py - Qualcomm firmware inspector (ELF / MBN / TME)  by Littlenine Ennea

    python qc_inspect.py <file> [-v|-vv]

reads what sectools "secure-image --inspect" reads: elf header, program headers,
mbn hash table segment (v3/v5/v6/v7/v8), common/qti/oem metadata, per-authority
signatures, cert chains + root hash, and tme debug policy (apdp dpr/slc).
structures reversed from sectools, not hardcoded magic-scan heuristics.
"""

import sys
import os
import re
import json
import math
import struct
import hashlib
import argparse
import subprocess
import tempfile
import collections
import xml.etree.ElementTree as ET

RESET, BOLD, CYAN, GREEN, YELLOW, RED, DIM = (
    "\033[0m", "\033[1m", "\033[96m", "\033[92m", "\033[93m", "\033[91m", "\033[2m")

def c(color, text):
    return f"{color}{text}{RESET}"

def header(title):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}\n{BOLD}{CYAN}  {title}{RESET}\n{BOLD}{CYAN}{'='*60}{RESET}")

def section(title):
    print(f"\n{BOLD}{YELLOW}[{title}]{RESET}")

def field(name, value, extra=""):
    extra = f"  {DIM}({extra}){RESET}" if extra else ""
    print(f"  {name:<30} {c(GREEN, str(value))}{extra}")

def hexdump(data, base=0, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {DIM}0x{base+i:08x}:{RESET}  {hx:<{width*3}}  {asc}")

def hexs(v):
    return f"0x{v:x}"

# elf constants (standard EM ids + descriptions, matches sectools naming)
ELF_MAGIC = b'\x7fELF'
EM = {0x00: "None", 0x01: "AT&T WE 32100", 0x02: "SPARC", 0x03: "x86", 0x08: "MIPS",
      0x14: "PowerPC", 0x16: "S390", 0x28: "ARM 32-bit architecture (AARCH32)",
      0x2A: "SuperH", 0x32: "IA-64", 0x3E: "x86-64",
      0xB7: "ARM 64-bit architecture (AARCH64)", 0xF3: "RISC-V"}
ELF_TYPE = {0: "NONE (No file type)", 1: "REL (Relocatable file)", 2: "EXEC (Executable file)",
            3: "DYN (Shared object file)", 4: "CORE (Core file)"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB", 6: "PHDR"}

# qualcomm p_flags high byte: segment type = bits 24..26, page mode = bit 20
P_FLAGS_OS_SEGMENT_TYPE_MASK = 0x07000000
P_FLAGS_OS_PAGE_MODE_MASK = 0x00100000
OS_SEG_TYPE = {0: "L4", 1: "AMSS", 2: "HASH", 3: "BOOT", 4: "L4BSP",
               5: "SWAPPED", 6: "SWAP_POOL", 7: "PHDR"}
OS_SEG_HASH, OS_SEG_PHDR = 2, 7

def os_segment_type(p_flags):
    return (p_flags & P_FLAGS_OS_SEGMENT_TYPE_MASK) >> 24

def os_segment_type_str(p_flags):
    t = os_segment_type(p_flags)
    if t == OS_SEG_HASH:
        return "HASH (Hash Table Segment)"
    if t == OS_SEG_PHDR:
        return "PHDR (Encapsulates ELF Header and Program Header Table)"
    return f"0x{t} (Meaning is OS specific)"

# hash table segment field decodings (sectools defines)
HASH_TABLE_ALGO = {0: ("NA", 0), 2: ("SHA256", 32), 3: ("SHA384", 48), 5: ("SHA512", 64),
                   0x80000002: ("SHA256-ZI", 32), 0x80000003: ("SHA384-ZI", 48),
                   0x80000005: ("SHA512-ZI", 64)}
MEASUREMENT_TARGET = {0: "Measurement not to be recorded",
                      1: "Hardware Measurement Register #1", 2: "Hardware Measurement Register #2",
                      3: "Firmware Measurement Register #1", 4: "Firmware Measurement Register #2",
                      5: "Firmware Measurement Register #3", 6: "Firmware Measurement Register #4"}
OEM_RCH_ALGO = {0: "NA", 2: "SHA256", 3: "SHA384", 5: "SHA512"}
OEM_LIFECYCLE = {1: "Development", 2: "Production"}
FALSE_TRUE = {1: "False", 2: "True"}
DEBUG_DESC = {1: "Nop", 2: "Disable", 3: "Enable (for devices with matching serial number)"}
NUM_SOC_HW_VERS, NUM_SERIALS = 12, 8

# metadata flags are 2-bit fields (FALSE=1, TRUE=2): (mask, label, is_debug)
META_FLAGS = [(3, "Bound to SoC Hardware Versions", False),
              (12, "Bound to Product Segment ID", False),
              (48, "Bound to JTAG ID", False),
              (192, "Bound to Serial Numbers", False),
              (768, "Bound to OEM ID", False),
              (3072, "Bound to OEM Product ID", False),
              (12288, "Bound to SoC Lifecycle State", False),
              (49152, "Bound to OEM Lifecycle State", False),
              (196608, "Bound to OEM Root Certificate Hash", False),
              (786432, "JTAG Debug", True),
              (3145728, "Transfer Root", False)]

def _lsb(mask):
    return (mask & -mask).bit_length() - 1

def _flag(flags, mask):
    return (flags & mask) >> _lsb(mask)

# tme tlv grammar: tag id -> (name, type) and enum decodes, from sectools tme_tags/tme_enums.json
TME_TAGS = {
    32896: ('EntitlementCertificate', 'map'),
    33025: ('CertificateVersion', 'int'),
    33026: ('KeyIdentifier', 'int'),
    33027: ('AlgorithmIdentifier', 'int'),
    33040: ('EntitlementChain', 'map'),
    33041: ('RootEntitlement', 'map'),
    33042: ('IntermediateEntitlement', 'map'),
    33152: ('Entitlements', 'map'),
    33279: ('Signature', 'byteArray'),
    33408: ('AttestationEntitlement', 'map'),
    33409: ('BootEntitlement', 'map'),
    33410: ('DebugEntitlement', 'map'),
    33411: ('CommandEntitlement', 'map'),
    33412: ('OemRootEntitlement', 'map'),
    33413: ('IntermediateAttestationCertificate', 'map'),
    33296: ('ConfigData', 'byteArray'),
    33424: ('DebugPolicyData', 'map'),
    33425: ('ImageDescriptor', 'map'),
    33426: ('RomPatchData', 'map'),
    33427: ('FuseOverwriteData', 'map'),
    33428: ('BootEntitlementData', 'map'),
    33431: ('AttestationData', 'map'),
    33536: ('InstanceVersion', 'int'),
    33537: ('SecurityVersion', 'int'),
    33552: ('AttestationClaimSetVector', 'int'),
    33553: ('AttestationModes', 'int'),
    33555: ('AttestationCBORContainer', 'byteArray'),
    33568: ('PublicKeyAttributes', 'int'),
    33584: ('AuthorizedDebugVector', 'byteArray'),
    33585: ('AuthorizedDebugOptions', 'int'),
    33586: ('AuthorizedTestSignedImageVector', 'byteArray'),
    33587: ('AuthorizedDebugIPScanDumpPolicyVector', 'byteArray'),
    33588: ('AuthorizedDebugQADDumpPolicyVector', 'byteArray'),
    33589: ('AuthorizedDebugMemDumpPolicyVector', 'byteArray'),
    33590: ('AuthorizedDebugRTQADDumpPolicyVector', 'byteArray'),
    33600: ('CommandAuthorizationVector', 'int'),
    33617: ('ImageDescriptorSoftwareComponentIdentifier', 'int'),
    33618: ('MeasurementRegisterTarget', 'int'),
    33632: ('DebugVector', 'byteArray'),
    33633: ('DebugOptions', 'int'),
    33634: ('CrashDumpVector', 'int'),
    33635: ('TestSignedImageVector', 'byteArray'),
    33636: ('DebugIPScanDumpPolicyVector', 'byteArray'),
    33637: ('DebugQADDumpPolicyVector', 'byteArray'),
    33638: ('DebugMemDumpPolicyVector', 'byteArray'),
    33639: ('DebugRTQADDumpPolicyVector', 'byteArray'),
    33640: ('RomIdentifier', 'int'),
    33641: ('RomPatch', 'byteArray'),
    33644: ('WriteProtectionOverwriteVector', 'long'),
    33645: ('OverwriteCommandSequence', 'byteArray'),
    33663: ('InstantiationConstraints', 'int'),
    33664: ('ChipConstraints', 'map'),
    33665: ('SubsystemAuthorizationVector', 'mapArray'),
    33666: ('DebugVectorToQad', 'byteArray'),
    33668: ('ImageDescHashValues', 'map'),
    33669: ('RomPatchDescriptor', 'mapArray'),
    33670: ('ImageDescAddressSize', 'map'),
    33672: ('SubsystemDebugOptions', 'mapArray'),
    33673: ('TestSignedImageHashList', 'mapArray'),
    33674: ('OemTestRootCaHashValues', 'map'),
    33675: ('FingerprintHashValue', 'map'),
    33676: ('OemCrashDumpPublicKey', 'map'),
    33680: ('PublicKey', 'map'),
    33792: ('RootKeysetVersion', 'int'),
    33793: ('SocHardwareVersion', 'int'),
    33795: ('OemIdentifier', 'int'),
    33796: ('OemProductIdentifier', 'int'),
    33797: ('SocLifeCycleState', 'int'),
    33799: ('SocFeatureIdentifier', 'int'),
    33800: ('SocJtagIdentifier', 'int'),
    33801: ('OemLifeCycleState', 'int'),
    33808: ('CurveIdentifier', 'int'),
    33809: ('PublicKeyValue', 'byteArray'),
    33826: ('BootSubsystemSoftwareComponentIdentifier', 'int'),
    33827: ('RootSigningCaIdentifier', 'int'),
    33856: ('HashAlgorithmIdentifier', 'int'),
    33857: ('HashArray', 'byteArray'),
    33864: ('ImageAddress', 'long'),
    33865: ('ImageSize', 'long'),
    33872: ('SubsysIdentifier', 'int'),
    33873: ('SubsysDebugOptions', 'int'),
    33926: ('HashValues', 'map'),
    33927: ('ChipUniqueIdentifier', 'map'),
    33928: ('OemRcHash', 'map'),
    33929: ('OemBatchKeyHash', 'map'),
    34064: ('ProductIdentifier', 'int'),
    34065: ('SerialNumber', 'intArray'),
    34304: ('BootManifest', 'map'),
    34305: ('BootManifestHashTable', 'map'),
    34306: ('BootManifestHashTableEntry', 'mapArray'),
    34307: ('ImageDescriptorArray', 'mapArray'),
    5: ('CmdShaInit', 'map'),
    6: ('CmdShaUpdate', 'map'),
    7: ('CmdShaFinal', 'map'),
    8: ('CmdShaRegionUpdate', 'map'),
    385: ('SvcSocProvisioning', 'map'),
    386: ('SvcImageAuthentication', 'map'),
    387: ('SvcAuthenticatedDebugReenable', 'map'),
    388: ('SvcRomPatch', 'map'),
    29061: ('SvcSpuProvisioning', 'map'),
    390: ('SvcDebugPolicy', 'map'),
    391: ('SvcSocActivation', 'map'),
    392: ('SvcDynamiceFuseOverwrite', 'map'),
    393: ('SvcStaticFuseOverwrite', 'map'),
    394: ('SvcBootEntitlement', 'map'),
    395: ('SvcTerminate', 'map'),
    396: ('SvcVerifyAttestation', 'map'),
    397: ('SvcSocTerminate', 'map'),
    398: ('SvcApmSocProvInit', 'map'),
    399: ('SvcApmSocProvision', 'map'),
    400: ('SvcApmCertCheck', 'map'),
    401: ('SvcCertOceEckaPullProvision', 'map'),
    49153: ('CmdMinorVersion', 'data_short'),
    49154: ('CmdMajorVersion', 'data_short'),
    49155: ('CmdStatus', 'data_short'),
    49169: ('CmdReserved1', 'reserve1'),
    49170: ('CmdReserved2', 'reserve2'),
    49171: ('CmdReserved3', 'reserve3'),
    49172: ('CmdReserved4', 'reserve4'),
    49173: ('CmdConstLen4', 'int'),
    49184: ('CmdAddress', 'int'),
    49185: ('CmdLength', 'int'),
    49186: ('CmdInfraNonce', 'data_byteArray'),
    49187: ('CmdSocNonce', 'data_byteArray'),
    49188: ('CmdInitialVector', 'data_byteArray'),
    49189: ('CmdSigningAlgorithmId', 'data_byte'),
    49190: ('CmdSignature', 'data_byteArray'),
    49191: ('EncryptedCommandSequence', 'data_byteArray'),
    49192: ('AeadMac', 'data_byteArray'),
    49193: ('CertLen', 'data_short'),
    49194: ('CertOffset', 'data_short'),
    49232: ('ShaMode', 'data_byte'),
    49233: ('ShaRegionId', 'data_short'),
    49409: ('CipherSuite', 'data_byte'),
    49410: ('FamilyKeySet', 'data_byte'),
    49411: ('DerivationKeyVersion', 'data_byte'),
    49412: ('DevelopmentMode', 'data_byte'),
    49665: ('CmdOemId', 'int'),
    49666: ('CmdModelId', 'int'),
    49921: ('CmdDebugOptions', 'data_byte'),
    50433: ('ApplianceEphemeralKey', 'data_byteArray'),
    50689: ('CurveIdentifierDataOnly', 'data_byte'),
    50945: ('CmdOperationalMode', 'data_byte'),
    65533: ('CertTodo', 'data_byte'),
    65534: ('CmdCryptoTodo', 'data_byte'),
    65535: ('CmdSvcTodo', 'data_byte'),
}

TME_ENUMS = {
    33026: ('exclusive', {1: 'QTI_ENTITLEMENT_ROOT_KID', 2: 'QTI_CODE_SIGNING_ROOT_KID', 3: 'OEM_ENTITLEMENT_KID', 4: 'INTERMEDIATE_CA_SIGNING_KID', 130: 'QTI_TEST_CODE_SIGNING_ROOT_KID'}),
    33027: ('exclusive', {0: 'NONE', 1: 'ECDSA_P384_SHA384', 2: 'ECDSA_P521_SHA512'}),
    33552: ('mask', {1: 'NONCE', 2: 'UE_ID', 4: 'SECURE_BOOT_STATE', 8: 'DEBUG_STATE', 16: 'SEC_VERS_TME_HW_AGENT_ROM', 32: 'SEC_VERS_TME_HW_CPU_ROM', 64: 'SEC_VERS_SOC_ROM', 128: 'SEC_VERS_TME_HW_CPU_IMAGE', 256: 'OEM_ID', 512: 'SP_ID', 1024: 'OEM_PRODUCT_ID', 2048: 'QTI_PRODUCT_ID', 8192: 'SOC_LCS', 16384: 'FEATURE_STATE', 32768: 'HW_STATE_REPORT', 65536: 'CLIENT_CONTEXT', 131072: 'ROOT_KEYSET_STATE_VECTOR', 262144: 'SOC_PROVISIONING_KEY_VERSION', 524288: 'MEASUREMENT_REGISTER_0', 1048576: 'MEASUREMENT_REGISTER_1'}),
    33553: ('exclusive', {1: 'PRIVACY_PRESERVING', 2: 'NONPRIVACY_PRESERVING'}),
    33568: ('mask', {0: 'NONE', 1: 'IS_DELEGATE_K_TEST', 2: 'IS_DELEGATE_K_CA'}),
    33585: ('mask', {0: 'NONE', 1: 'PERMANENT_UNLOCK', 2: 'PERSIST_ON_RESET', 4: 'ASSERT_QTI_OWNERSHIP', 8: 'FORCE_SEQ_ROM', 16: 'DISABLE_SYSTEM_WATCHDOG', 32: 'ALLOW_SYSTEM_WATCHDOG_ACCESS'}),
    33600: ('mask', {2: 'SPR', 4: 'IAR', 8: 'ADRR', 16: 'RPR', 64: 'DPR', 128: 'SAR', 256: 'DFOR', 512: 'SFOR', 1024: 'BER', 2048: 'STR'}),
    33617: ('exclusive', {2: 'MODEM_SS_SWID', 3: 'VIP_SS_SWID', 5: 'TZ_CONFIG_SS_SWID', 7: 'QTEE_SS_SWID', 9: 'UEFI_SS_SWID', 21: 'QHEE_SS_SWID', 31: 'CMNLIB_SS_SWID', 32: 'SHRM_SS_SWID', 33: 'AOP_SS_SWID', 34: 'OEM_MISC_SS_SWID', 35: 'QTI_MISC_SS_SWID', 36: 'QUPV3_SS_SWID', 37: 'XBL_CONFIG_SS_SWID', 39: 'UEFI_FV_SS_SWID', 43: 'SEC_ELF_SS_SWID', 49: 'CPUCP_SS_SWID', 50: 'APP_SS_SWID', 53: 'TME_FW_SS_SWID', 54: 'XBL_SC_SS_SWID', 55: 'TME_SEQ_SS_SWID', 56: 'BTSS_SWID', 65: 'XBL_SC_EXT_SS_SWID', 66: 'XBL_RAM_DUMP_SS_SWID', 72: 'BTSS_LIC_SWID', 73: 'BTSS_CFG_SWID', 74: 'OEM_BOOT_MANIF_HASH_TBL_SWID', 75: 'QTI_BOOT_MANIF_HASH_TBL_SWID', 77: 'CPUSYS_VM_SS_SWID', 78: 'QTI_BOOT_MANIFEST_SWID', 79: 'OEM_BOOT_MANIFEST_SWID', 80: 'UPDATE_MANIFEST_SWID', 106: 'MVM_FW_SS_SWID', 137: 'SOCCP_DEBUG_SS_SWID', 145: 'PDP_SS_SWID', 148: 'TME_CONFIG', 149: 'XBL_AC_CONFIG', 150: 'TZ_AC_CONFIG', 151: 'HYP_AC_CONFIG', 152: 'OOBMSS_TEE', 153: 'OOBMSS_QC_DTB', 154: 'OOBMSS_NS', 161: 'TZ_QTI_CONFIG', 512: 'TME_SIGNED_CMD_SWID'}),
    33618: ('exclusive', {0: 'NA', 1: 'HMR_1', 2: 'HMR_2', 3: 'FMR_1', 4: 'FMR_2', 5: 'FMR_3', 6: 'FMR_4'}),
    33633: ('mask', {0: 'NONE', 1: 'PERMANENT_UNLOCK', 2: 'PERSIST_ON_RESET', 4: 'ASSERT_QTI_OWNERSHIP', 8: 'FORCE_SEQ_ROM', 16: 'DISABLE_SYSTEM_WATCHDOG', 32: 'ALLOW_SYSTEM_WATCHDOG_ACCESS'}),
    33634: ('mask', {1: 'MINI_DUMP', 2: 'NS_FULL_DUMP', 4: 'SEC_FULL_DUMP'}),
    33640: ('exclusive', {1: 'TME_SEQ_RID', 2: 'TME_CPU_RID', 3: 'SOC_RID', 4: 'TME_SEQ_ROM_RID'}),
    33663: ('mask', {1: 'IS_SOC_ROOT_KSET_VER_BOUND', 2: 'IS_SOC_HW_VERSION_BOUND', 4: 'IS_CHIP_UNIQUE_ID_BOUND', 8: 'IS_OEM_ID_BOUND', 16: 'IS_OEM_PROD_ID_BOUND', 32: 'IS_OEM_RC_HASH_BOUND', 64: 'IS_SOC_LCS_BOUND', 128: 'IS_FEAT_ID_BOUND', 256: 'IS_JTAG_ID_BOUND', 512: 'IS_NONCE_BOUND', 1024: 'IS_FINGERPRINT_BOUND', 2048: 'IS_QTI_OWNERSHIP_ASSERTION_BOUND', 4096: 'IS_OEM_LCS_BOUND', 8192: 'IS_OEM_BATCH_KEY_HASH_BOUND'}),
    33797: ('mask', {1: 'BLANK', 2: 'PERSONALIZED', 32: 'OPERATIONAL_EXT', 128: 'RMA', 2048: 'OPERATIONAL_INT', 16384: 'RECOVERY', 32768: 'TERMINATED'}),
    33801: ('mask', {2: 'DEVELOPMENT', 13: 'PRODUCTION'}),
    33808: ('exclusive', {1: 'P-256', 2: 'P-384', 3: 'P-521'}),
    33826: ('exclusive', {2: 'MODEM_SS_SWID', 3: 'VIP_SS_SWID', 5: 'TZ_CONFIG_SS_SWID', 7: 'QTEE_SS_SWID', 9: 'UEFI_SS_SWID', 21: 'QHEE_SS_SWID', 31: 'CMNLIB_SS_SWID', 32: 'SHRM_SS_SWID', 33: 'AOP_SS_SWID', 34: 'OEM_MISC_SS_SWID', 35: 'QTI_MISC_SS_SWID', 36: 'QUPV3_SS_SWID', 37: 'XBL_CONFIG_SS_SWID', 39: 'UEFI_FV_SS_SWID', 43: 'SEC_ELF_SS_SWID', 49: 'CPUCP_SS_SWID', 50: 'APP_SS_SWID', 53: 'TME_FW_SS_SWID', 54: 'XBL_SC_SS_SWID', 55: 'TME_SEQ_SS_SWID', 56: 'BTSS_SWID', 65: 'XBL_SC_EXT_SS_SWID', 66: 'XBL_RAM_DUMP_SS_SWID', 72: 'BTSS_LIC_SWID', 73: 'BTSS_CFG_SWID', 74: 'OEM_BOOT_MANIF_HASH_TBL_SWID', 75: 'QTI_BOOT_MANIF_HASH_TBL_SWID', 77: 'CPUSYS_VM_SS_SWID', 78: 'QTI_BOOT_MANIFEST_SWID', 79: 'OEM_BOOT_MANIFEST_SWID', 80: 'UPDATE_MANIFEST_SWID', 106: 'MVM_FW_SS_SWID', 137: 'SOCCP_DEBUG_SS_SWID', 145: 'PDP_SS_SWID', 148: 'TME_CONFIG', 149: 'XBL_AC_CONFIG', 150: 'TZ_AC_CONFIG', 151: 'HYP_AC_CONFIG', 152: 'OOBMSS_TEE', 153: 'OOBMSS_QC_DTB', 154: 'OOBMSS_NS', 161: 'TZ_QTI_CONFIG', 512: 'TME_SIGNED_CMD_SWID'}),
    33827: ('mask', {1: 'QTI_CA_ID', 2: 'OEM_CA_ID', 4: 'DELEGATE_K_ID'}),
    33856: ('exclusive', {2: 'SHA256', 3: 'SHA384', 5: 'SHA512'}),
    33872: ('exclusive', {0: 'TME_SEQ_SS_MSID', 1: 'TME_CPU_SS_MSID', 2: 'AOP_SS_MSID', 3: 'SHRM_SS_MSID', 4: 'CPUCP_SS_MSID', 16: 'AP_SEC_SS_MSID', 17: 'AP_NSEC_SS_MSID', 18: 'HYP_SS_MSID', 32: 'MODEM_SS_MSID', 48: 'ADSP_SS_MSID', 49: 'CDSP_SS_MSID', 50: 'SLPI_SS_MSID', 51: 'CAMERA_SS_MSID', 52: 'LPASS_SS_MSID', 53: 'NSP_SS_MSID', 54: 'GPU_SS_MSID', 55: 'WLAN_SS_MSID', 56: 'SOCCP_SS_MSID', 57: 'DCP_SS_MSID', 58: 'OOB_NSEC_SS_MSID', 59: 'OOB_SEC_SS_MSID'}),
    49189: ('exclusive', {0: 'NONE', 1: 'ECDSA_P384_SHA384', 2: 'ECDSA_P521_SHA512'}),
    49412: ('exclusive', {0: 'FALSE', 1: 'TRUE'}),
    50689: ('exclusive', {1: 'P-256', 2: 'P-384', 3: 'P-521'}),
    50945: ('exclusive', {0: 'OPERATIONAL_EXT', 1: 'OPERATIONAL_INT'}),
}

# tme parent tag -> ordered child tag ids (for positional cmd headers), from tme_relations.json
TME_RELATIONS = {
    32896: [33025, 33026, 33027, 33152, 33279],
    33152: [33408, 33409, 33410, 33411, 33412, 33413],
    33408: [33536, 33555, 33663, 33664, 33680],
    33413: [33536, 33555, 33663, 33664, 33680],
    33409: [33536, 33568, 33663, 33664, 33665, 33680],
    33410: [33536, 33584, 33585, 33586, 33587, 33588, 33589, 33590, 33663, 33664, 33680],
    33411: [33536, 33600, 33663, 33664, 33680],
    33412: [33536, 33568, 33663, 33664, 33680],
    33424: [33632, 33633, 33634, 33635, 33636, 33637, 33638, 33639, 33664, 33672, 33673, 33674, 33675, 33676],
    33425: [33537, 33617, 33618, 33664, 33668, 33670, 33675],
    33426: [33664, 33669, 33675],
    33427: [33644, 33645, 33664, 33675],
    33428: [33664, 33675],
    33431: [33664, 33675],
    33664: [33792, 33793, 33795, 33796, 33797, 33799, 33800, 33801, 33927, 33928, 33929],
    33665: [33826, 33827],
    33668: [33856, 33857],
    33669: [33537, 33640, 33641],
    33670: [33864, 33865],
    33672: [33872, 33873],
    33673: [33826, 33926],
    33674: [33856, 33857],
    33675: [33856, 33857],
    33676: [33808, 33809],
    33680: [33808, 33809],
    33926: [33856, 33857],
    33927: [34064, 34065],
    33928: [33856, 33857],
    33929: [33856, 33857],
    34305: [34306],
    34306: [33826, 33926],
    34307: [33537, 33617, 33618, 33664, 33668, 33670, 33675],
    5: [49232, 49169],
    6: [49170, 49184, 49185],
    7: [49170],
    8: [49233],
    385: [49153, 49154, 49409, 49410, 49411, 49412, 49186, 49187, 49188, 49191, 49192],
    386: [49153, 49154, 49189, 49171, 33425, 33279, 32896],
    387: [49153, 49154, 49189, 49169, 49921, 49169, 49187, 33632, 49190, 32896],
    388: [49153, 49154, 49189, 49170, 49412, 33426, 33279, 32896],
    398: [49153, 49154, 49171, 49412],
    399: [49153, 49154, 49188, 49191, 49192, 49186],
    400: [49153, 49154, 49193, 49194, 50689, 49171],
    401: [49153, 49154, 50689, 49171],
    29061: [49153, 49154, 49409, 49171, 49186, 49187, 49188, 50433, 49191, 49192],
    390: [49153, 49154, 49189, 49171, 33424, 33279, 32896],
    391: [49153, 49154, 49189, 49169, 50945, 49169, 33296, 49187, 49173, 49172, 49190, 32896],
    392: [49153, 49154, 49189, 49171, 33644, 49187, 49173, 49172, 49190, 32896],
    393: [49153, 49154, 49189, 49171, 33427, 33279, 32896],
    394: [49153, 49154, 49189, 49171, 33428, 33279, 32896],
    395: [49153, 49154],
    396: [49153, 49154, 33431, 33040],
    397: [49153, 49154, 33664, 32896],
    34304: [386, 34305],
    33040: [33042, 33041],
    33041: [32896],
    33042: [32896],
}

# non-elf / container diagnostics
KNOWN_CONTAINER_MAGIC = [
    (b'.rtc', 'Encrypted/obfuscated container (".rtc") - decrypt first'),
    (b'PK\x03\x04', "ZIP archive"), (b'7z\xbc\xaf\x27\x1c', "7-Zip archive"),
    (b'\x1f\x8b', "gzip stream"), (b'\x78\x9c', "zlib stream"),
    (b'\x28\xb5\x2f\xfd', "zstd stream"), (b'BZh', "bzip2 stream"),
    (b'\xfd7zXZ\x00', "xz stream"), (b'ANDROID!', "Android boot image"),
    (b'-rom1fs-', "romfs"), (b'UBI#', "UBI image")]

def _entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(data).values())

def _ascii(b):
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)

def diagnose_not_elf(data):
    print(c(RED, "  Not an ELF: header does not start with 7f 45 4c 46"))
    field("First 4 bytes", f"{data[:4].hex()}  ({_ascii(data[:4])!r})")
    ent = _entropy(data)
    field("File entropy", f"{ent:.4f} bits/byte", "~8.0 -> encrypted or compressed" if ent > 7.9 else "")
    for magic, desc in KNOWN_CONTAINER_MAGIC:
        if data.startswith(magic):
            field("Container detected", desc)
            break
    if b'TME' in data[:64] or b'DPR' in data[:256]:
        field("Possible TME image", "Trust Management Engine container, not an ELF hash-segment image")
    pos = data.find(ELF_MAGIC)
    if pos > 0:
        field("ELF magic found at", f"0x{pos:x}", "prepended header - re-parsing there")
        return pos
    field("ELF magic in file", "not found anywhere")
    if ent > 7.9:
        print(c(YELLOW, "  => payload is ENCRYPTED; decrypt/unpack before inspecting."))
    return None

def parse_elf(data, verbose, _base=0):
    section("ELF Header")
    if data[:4] != ELF_MAGIC:
        off = diagnose_not_elf(data)
        if off is not None:
            return parse_elf(data[off:], verbose, _base + off)
        return None, []

    is64 = data[4] == 2
    field("Magic", ' '.join(f'{b:02x}' for b in data[:16]))
    field("Class", "ELF64" if is64 else "ELF32")
    field("Data", "2's complement, little endian" if data[5] == 1 else "2's complement, big endian")
    field("Version", f"{data[6]} (current)" if data[6] == 1 else data[6])
    field("OS/ABI", "UNIX - System V" if data[7] == 0 else f"0x{data[7]:x}")
    field("ABI Version", data[8])
    e_type, machine = struct.unpack_from('<HH', data, 16)
    e_version = struct.unpack_from('<I', data, 20)[0]
    field("Type", ELF_TYPE.get(e_type, f"0x{e_type:x}"))
    field("Machine", f"{EM.get(machine, 'Unknown')}  (0x{machine:02x})")
    field("Version", f"0x{e_version:x}")

    if is64:
        e_entry, e_phoff, e_shoff, e_flags = struct.unpack_from('<QQQI', data, 24)
        e_ehsize, e_phentsize, e_phnum, _, e_shnum, _ = struct.unpack_from('<HHHHHH', data, 52)
    else:
        e_entry, e_phoff, e_shoff, e_flags = struct.unpack_from('<IIII', data, 24)
        e_ehsize, e_phentsize, e_phnum, _, e_shnum, _ = struct.unpack_from('<HHHHHH', data, 40)
    field("Entry point address", f"0x{e_entry:08x}")
    field("Start of program headers", f"{e_phoff} (bytes into file)")
    field("Start of section headers", f"{e_shoff} (bytes into file)")
    field("Flags", f"0x{e_flags:x}")
    field("Size of this header", f"{e_ehsize} (bytes)")
    field("Size of program headers", f"{e_phentsize} (bytes)")
    field("Number of program headers", e_phnum)
    field("Number of section headers", e_shnum)

    w = 16 if is64 else 8
    hx = lambda v: f"0x{v:0{w}x}"
    section("Program Headers")
    print(f"  {'Idx':<4}{'Type':<8}{'Offset':<{w+4}}{'VirtAddr':<{w+4}}{'FileSize':<{w+4}}"
          f"{'MemSize':<{w+4}}{'Flg':<5}{'Align':<{w+4}}{'OS Segment Type'}")
    print(f"  {'-'*110}")
    segments, hash_phdr = [], None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags, p_off, p_va, p_pa, p_fsz, p_msz, p_al = struct.unpack_from('<IIQQQQQQ', data, off)
        else:
            p_type, p_off, p_va, p_pa, p_fsz, p_msz, p_flags, p_al = struct.unpack_from('<IIIIIIII', data, off)
        rwe = ('R' if p_flags & 4 else '-') + ('W' if p_flags & 2 else '-') + ('E' if p_flags & 1 else '-')
        ts = PT.get(p_type, f"0x{p_type:x}")
        print(f"  {i:<4}{ts:<8}{hx(p_off):<{w+4}}{hx(p_va):<{w+4}}{hx(p_fsz):<{w+4}}"
              f"{hx(p_msz):<{w+4}}{rwe:<5}{hx(p_al):<{w+4}}{os_segment_type_str(p_flags)}")
        seg = {'offset': p_off, 'filesz': p_fsz, 'os_type': os_segment_type(p_flags)}
        segments.append(seg)
        if seg['os_type'] == OS_SEG_HASH and p_fsz:
            hash_phdr = seg
    return {'is64': is64, 'hash_phdr': hash_phdr}, segments

# openssl cert helpers
_cert_cache = {}
OPENSSL_SIGALG = {
    'ecdsa-with-sha384': ('ECDSA', 'SHA384'), 'ecdsa-with-sha256': ('ECDSA', 'SHA256'),
    'ecdsa-with-sha512': ('ECDSA', 'SHA512'), 'sha256withrsaencryption': ('RSA', 'SHA256'),
    'sha384withrsaencryption': ('RSA', 'SHA384'), 'sha512withrsaencryption': ('RSA', 'SHA512'),
    'sha1withrsaencryption': ('RSA', 'SHA1')}

def _openssl_text(der):
    key = hashlib.sha256(der).hexdigest()
    if key in _cert_cache:
        return _cert_cache[key]
    out = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
            f.write(der); tmp = f.name
        r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', tmp, '-text', '-noout'],
                           capture_output=True, text=True, timeout=8)
        os.unlink(tmp)
        out = r.stdout if r.returncode == 0 else None
    except Exception:
        out = None
    _cert_cache[key] = out
    return out

def cert_details(der):
    txt = _openssl_text(der)
    d = {'subject': None, 'issuer': None, 'not_before': None, 'not_after': None, 'sig_alg': None,
         'hash_alg': None, 'algorithm': None, 'curve': None, 'key_size': None, 'exponent': None,
         'padding': None, 'eku': None, 'ou': []}
    if not txt:
        return d
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith('Subject:'):
            d['subject'] = s[8:].strip()
        elif s.startswith('Issuer:'):
            d['issuer'] = s[7:].strip()
        elif s.startswith('Not Before:'):
            d['not_before'] = s[11:].strip()
        elif s.startswith('Not After'):
            d['not_after'] = s.split(':', 1)[1].strip()
        elif s.startswith('Signature Algorithm:') and not d['sig_alg']:
            d['sig_alg'] = s.split(':', 1)[1].strip()
        elif 'Public-Key:' in s:                     # libressl: "RSA Public-Key: (2048 bit)"
            m = re.search(r'\((\d+) bit\)', s)
            if m:
                d['key_size'] = int(m.group(1))
        elif s.startswith('ASN1 OID:'):
            d['curve'] = s.split(':', 1)[1].strip()
        elif s.startswith('Exponent:'):
            m = re.search(r'(\d+)', s)
            if m:
                d['exponent'] = int(m.group(1))
        elif 'Code Signing' in s:
            d['eku'] = 'Code Signing'
    ah = OPENSSL_SIGALG.get((d['sig_alg'] or '').lower())
    if ah:
        d['algorithm'], d['hash_alg'] = ah
        if d['algorithm'] == 'RSA':
            d['padding'] = 'PKCS'
    # v3 secboot binds via attest-cert OU fields "NN <hex> NAME"
    if d['subject']:
        for fld in re.split(r',\s*(?=[A-Za-z]+\s*=)', d['subject']):
            m = re.match(r'OU\s*=\s*([0-9A-Fa-f]{2})\s+([0-9A-Fa-f ]+?)\s+([A-Za-z0-9_]+)\s*$', fld.strip())
            if m:
                d['ou'].append((m.group(3), m.group(2).replace(' ', '').lower()))
    return d

def parse_certs(region):
    certs = []
    for m in re.finditer(b'\x30\x82', region):
        off = m.start()
        if off + 4 > len(region):
            continue
        clen = struct.unpack_from('>H', region, off + 2)[0] + 4
        if not (100 < clen <= 8192) or off + clen > len(region):
            continue
        der = bytes(region[off:off + clen])
        det = cert_details(der)
        if det['subject'] or det['issuer']:
            certs.append({'offset': off, 'der': der, 'info': det})
    seen, uniq = set(), []
    for x in certs:
        h = hashlib.sha256(x['der']).hexdigest()
        if h not in seen:
            seen.add(h); uniq.append(x)
    return uniq

def classify_chain(certs):
    roots = [x for x in certs if x['info']['subject'] and x['info']['subject'] == x['info']['issuer']]
    root = roots[0] if roots else None
    issuers = {y['info']['issuer'] for y in certs}
    leaves = [x for x in certs if x['info']['subject'] not in issuers]
    attest = leaves[0] if leaves else None
    cas = [x for x in certs if x is not root and x is not attest]
    return attest, cas, root

# signature r/s (ecdsa der)
def _der_len(b, i):
    n = b[i]; i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7f
    return int.from_bytes(b[i:i + k], 'big'), i + k

def cert_signature_bytes(der):
    # x509 = SEQ{ tbs, sigAlg, sigValue BITSTRING }; return sigValue content
    try:
        if der[0] != 0x30:
            return None
        _, i = _der_len(der, 1)
        tl, j = _der_len(der, i + 1); i = j + tl
        al, j = _der_len(der, i + 1); i = j + al
        if der[i] != 0x03:
            return None
        bl, j = _der_len(der, i + 1)
        return bytes(der[j + 1:j + bl])
    except Exception:
        return None

def extract_rs(sig):
    try:
        if sig[0] != 0x30:
            return None
        i = 2 if sig[1] < 0x80 else 2 + (sig[1] - 0x80)
        if sig[i] != 0x02:
            return None
        rlen = sig[i + 1]; r = sig[i + 2:i + 2 + rlen]; j = i + 2 + rlen
        if sig[j] != 0x02:
            return None
        slen = sig[j + 1]; s = sig[j + 2:j + 2 + slen]
        return rlen, r.lstrip(b'\x00'), slen, s.lstrip(b'\x00')
    except Exception:
        return None

def sig_properties(sig_bytes, attest_info):
    if attest_info.get('algorithm'):
        field("Algorithm", attest_info['algorithm'])
    if attest_info.get('hash_alg'):
        field("Hash Algorithm", attest_info['hash_alg'])
    if attest_info.get('curve'):
        field("Curve", attest_info['curve'])
    rs = extract_rs(bytes(sig_bytes))
    if rs:
        rlen, r, slen, s = rs
        field("R Size", f"{rlen} (bytes)"); field("S Size", f"{slen} (bytes)")
        field("R", "0x" + r.hex()); field("S", "0x" + s.hex())
    if attest_info.get('key_size'):
        field("Key Size", attest_info['key_size'])
    if attest_info.get('exponent') is not None:
        field("Exponent", attest_info['exponent'])
    if attest_info.get('padding'):
        field("Padding", attest_info['padding'])

def cert_role_properties(cert):
    info = cert['info']
    if info.get('eku'):
        field("Extended Key Usage", info['eku'])
    if info.get('algorithm'):
        field("Signature Algorithm", info['algorithm'])
    if info.get('hash_alg'):
        field("Hash Algorithm", info['hash_alg'])
    if info.get('curve'):
        field("Curve", info['curve'])
    if info.get('algorithm') == 'ECDSA':                # cert's own signature r/s
        rs = extract_rs(cert_signature_bytes(cert['der']) or b'')
        if rs:
            rlen, r, slen, s = rs
            field("R Size", f"{rlen} (bytes)"); field("S Size", f"{slen} (bytes)")
            field("R", "0x" + r.hex()); field("S", "0x" + s.hex())
    if info.get('key_size'):
        field("Key Size", info['key_size'])
    if info.get('exponent') is not None:
        field("Exponent", info['exponent'])
    if info.get('padding'):
        field("Padding", info['padding'])

# metadata
def print_common_metadata(cm):
    if len(cm) < 24:
        return None
    maj, minr, sw_id, sec_sw_id, alg, mrt = struct.unpack_from('<IIIIII', cm, 0)
    section("Common Metadata")
    field("Major Version", maj); field("Minor Version", minr)
    field("Software ID", hexs(sw_id)); field("Secondary Software ID", hexs(sec_sw_id))
    field("Hash Table Algorithm", HASH_TABLE_ALGO.get(alg, (hexs(alg), 0))[0])
    field("Measurement Register Target", MEASUREMENT_TARGET.get(mrt, hexs(mrt)))
    return HASH_TABLE_ALGO.get(alg, ("Unknown", 48))

def print_authority_metadata(md, title):
    if len(md) < 224:
        return
    fmt = '<' + 'IIII' + 'I' * NUM_SOC_HW_VERS + 'II' + 'Q' * NUM_SERIALS + 'IIIII' + '64s' + 'I'
    v = struct.unpack_from(fmt, md, 0)
    maj, minr, arb, mrc = v[0], v[1], v[2], v[3]
    soc_hw = [x for x in v[4:4 + NUM_SOC_HW_VERS] if x]
    seg_or_feat = v[4 + NUM_SOC_HW_VERS]
    jtag = v[5 + NUM_SOC_HW_VERS]
    serials = [x for x in v[6 + NUM_SOC_HW_VERS:6 + NUM_SOC_HW_VERS + NUM_SERIALS] if x]
    b = 6 + NUM_SOC_HW_VERS + NUM_SERIALS
    oem_id, oem_prod, soc_lc, oem_lc, rch_algo = v[b:b + 5]
    rch, flags = v[b + 5], v[b + 6]
    is_v3meta = (maj == 3)

    section(title)
    field("Major Version", maj); field("Minor Version", minr)
    field("Anti-Rollback Version", hexs(arb)); field("Root Certificate Index", mrc)
    if soc_hw:
        field("SoC Hardware Version" if len(soc_hw) == 1 else "SoC Hardware Versions",
              " and ".join(hexs(x) for x in soc_hw))
    field("Product Segment ID" if is_v3meta else "SoC Feature ID", hexs(seg_or_feat))
    field("JTAG ID", hexs(jtag))
    if serials:
        field("Serial Number" if len(serials) == 1 else "Serial Numbers",
              " and ".join(hexs(x) for x in serials))
    field("OEM ID", hexs(oem_id)); field("OEM Product ID", hexs(oem_prod))
    field("OEM Lifecycle State", OEM_LIFECYCLE.get(oem_lc, hexs(oem_lc)))
    field("OEM Root Certificate Hash Algorithm", OEM_RCH_ALGO.get(rch_algo, hexs(rch_algo)))
    if rch_algo in (2, 3, 5):
        sz = {2: 32, 3: 48, 5: 64}[rch_algo]
        field("OEM Root Certificate Hash", "0x" + rch[64 - sz:].hex())
    for mask, label, is_debug in META_FLAGS:
        if mask == 12:
            label = "Bound to Product Segment ID" if is_v3meta else "Bound to SoC Feature ID"
        val = _flag(flags, mask)
        if is_debug:
            field("JTAG Debug", DEBUG_DESC.get(val, hexs(val)))
        else:
            field(label, FALSE_TRUE.get(val, hexs(val)))

# hash table segment - version 7 (ecdsa / metadata)
def parse_v7(seg):
    _res, ver, cms, qms, oms, hts, qss, qcs, oss, ocs = struct.unpack_from('<IIIIIIIIII', seg, 0)
    section("Hash Table Segment Header")
    field("Version", ver)
    field("Common Metadata Size", f"{cms} (bytes)")
    field("QTI Metadata Size", f"{qms} (bytes)")
    field("OEM Metadata Size", f"{oms} (bytes)")
    field("Hash Table Size", f"{hts} (bytes)")
    field("QTI Signature Size", f"{qss} (bytes)")
    field("QTI Certificate Chain Size", f"{qcs} (bytes)")
    field("OEM Signature Size", f"{oss} (bytes)")
    field("OEM Certificate Chain Size", f"{ocs} (bytes)")

    o = 40
    cm = seg[o:o + cms]; o += cms
    qm = seg[o:o + qms]; o += qms
    om = seg[o:o + oms]; o += oms
    ht = seg[o:o + hts]; o += hts
    qsig = seg[o:o + qss]; o += qss
    qcert = seg[o:o + qcs]; o += qcs
    osig = seg[o:o + oss]; o += oss
    ocert = seg[o:o + ocs]; o += ocs
    padding = seg[o:]

    algo = print_common_metadata(cm) or ("SHA384", 48)
    if qms:
        print_authority_metadata(qm, "QTI Metadata")
    if oms:
        print_authority_metadata(om, "OEM Metadata")

    entry_sz = algo[1] or 48
    print_hash_entries(ht, entry_sz)

    roots = []
    for auth, sig, cert in (("QTI", qsig, qcert), ("OEM", osig, ocert)):
        if sig or cert:
            roots.append(print_authority_signing(auth, sig, cert))

    section("Hash Table Segment Properties")
    field("Hash Table Entry Size", f"{entry_sz} (bytes)")
    qd, od = v7_data_to_sign(seg, 'QTI'), v7_data_to_sign(seg, 'OEM')
    field("Hash of QTI Data (SHA256)", "0x" + hashlib.sha256(qd).hexdigest())
    field("Hash of QTI Data (SHA384)", "0x" + hashlib.sha384(qd).hexdigest())
    field("Hash of OEM Data (SHA256)", "0x" + hashlib.sha256(od).hexdigest())
    field("Hash of OEM Data (SHA384)", "0x" + hashlib.sha384(od).hexdigest())
    field("Padding", f"{len(padding)} (bytes)")
    return [r for r in roots if r]

def v7_data_to_sign(seg, authority):
    # sectools get_data_to_sign: zero the other authority's sig/cert sizes, mask
    # (zero) the other authority's metadata, then header + hash_table.
    _res, ver, cms, qms, oms, hts, qss, qcs, oss, ocs = struct.unpack_from('<IIIIIIIIII', seg, 0)
    o = 40
    cm = bytes(seg[o:o + cms]); o += cms
    qm = bytes(seg[o:o + qms]); o += qms
    om = bytes(seg[o:o + oms]); o += oms
    ht = bytes(seg[o:o + hts])
    h = bytearray(seg[0:40])
    if authority == 'QTI':
        struct.pack_into('<II', h, 0x20, 0, 0)       # oem sig/cert size -> 0
        om = b'\x00' * oms
    else:
        struct.pack_into('<II', h, 0x18, 0, 0)       # qti sig/cert size -> 0
        qm = b'\x00' * qms
    return bytes(h) + cm + qm + om + ht

# hash table segment - version 3 (rsa / cert-ou binding)
def parse_v3(seg):
    (boot_id, ver, reserved, dest_ptr, image_size, hts,
     oem_sig_ptr, oem_sig_size, oem_cert_ptr, oem_cert_size) = struct.unpack_from('<IIIIIIIIII', seg, 0)
    section("Hash Table Segment Header")
    field("Boot Image ID", hexs(boot_id)); field("Version", ver)
    field("Image Destination Pointer", f"0x{dest_ptr:08x}")
    field("Image Size", f"{image_size} (Size of data following Hash Table Segment Header)")
    field("Hash Table Size", f"{hts} (bytes)")
    field("OEM Signature Pointer", f"0x{oem_sig_ptr:08x}")
    field("OEM Signature Size", f"{oem_sig_size} (bytes)")
    field("OEM Certificate Chain Pointer", f"0x{oem_cert_ptr:08x}")
    field("OEM Certificate Chain Size", f"{oem_cert_size} (bytes)")

    o = 40
    ht = seg[o:o + hts]; o += hts
    osig = seg[o:o + oem_sig_size]; o += oem_sig_size
    ocert = seg[o:o + oem_cert_size]

    entry_sz = 32 if hts % 32 == 0 else (48 if hts % 48 == 0 else 32)
    print_hash_entries(ht, entry_sz)

    roots = []
    if oem_sig_size or oem_cert_size:
        roots.append(print_authority_signing("OEM", osig, ocert, show_ou=True))

    section("Hash Table Segment Properties")
    field("Hash Table Algorithm", "SHA256" if entry_sz == 32 else "SHA384")
    field("Hash Table Entry Size", f"{entry_sz} (bytes)")
    qd, od = v3_data_to_sign(seg, 'QTI', hts), v3_data_to_sign(seg, 'OEM', hts)
    field("Hash of QTI Data (SHA256)", "0x" + hashlib.sha256(qd).hexdigest())
    field("Hash of QTI Data (SHA384)", "0x" + hashlib.sha384(qd).hexdigest())
    field("Hash of OEM Data (SHA256)", "0x" + hashlib.sha256(od).hexdigest())
    field("Hash of OEM Data (SHA384)", "0x" + hashlib.sha384(od).hexdigest())
    return [r for r in roots if r]

def v3_data_to_sign(seg, authority, hts):
    boot_id, ver, reserved, dest_ptr, image_size, hts0, sptr, ssz, cptr, csz = struct.unpack_from('<IIIIIIIIII', seg, 0)
    ht = bytes(seg[40:40 + hts])
    m = 0xFFFFFFFF
    if authority == 'QTI':
        ssz = csz = 0
    sptr = (dest_ptr + hts) & m
    cptr = (dest_ptr + hts + ssz) & m
    h = struct.pack('<IIIIIIIIII', boot_id, ver, reserved, dest_ptr, image_size, hts, sptr, ssz, cptr, csz)
    return h + ht

# hash table segment - version 8 (v7 metadata + dual signatures per authority)
def parse_v8(seg):
    h = struct.unpack_from('<IIIIIIIIIIIIII', seg, 0)
    _res, ver, cms, qms, oms, hts, qs1, qc1, qs2, qc2, os1, oc1, os2, oc2 = h
    section("Hash Table Segment Header")
    field("Version", ver)
    field("Common Metadata Size", f"{cms} (bytes)")
    field("QTI Metadata Size", f"{qms} (bytes)")
    field("OEM Metadata Size", f"{oms} (bytes)")
    field("Hash Table Size", f"{hts} (bytes)")
    field("QTI Signature 1 Size", f"{qs1} (bytes)")
    field("QTI Certificate Chain 1 Size", f"{qc1} (bytes)")
    field("QTI Signature 2 Size", f"{qs2} (bytes)")
    field("QTI Certificate Chain 2 Size", f"{qc2} (bytes)")
    field("OEM Signature 1 Size", f"{os1} (bytes)")
    field("OEM Certificate Chain 1 Size", f"{oc1} (bytes)")
    field("OEM Signature 2 Size", f"{os2} (bytes)")
    field("OEM Certificate Chain 2 Size", f"{oc2} (bytes)")
    o = 56
    cm = seg[o:o + cms]; o += cms
    qm = seg[o:o + qms]; o += qms
    om = seg[o:o + oms]; o += oms
    ht = seg[o:o + hts]; o += hts
    regions = []
    for lbl, ssz, csz in (("QTI 1", qs1, qc1), ("QTI 2", qs2, qc2), ("OEM 1", os1, oc1), ("OEM 2", os2, oc2)):
        sig = seg[o:o + ssz]; o += ssz
        cert = seg[o:o + csz]; o += csz
        regions.append((lbl, sig, cert))
    algo = print_common_metadata(cm) or ("SHA384", 48)
    if qms:
        print_authority_metadata(qm, "QTI Metadata")
    if oms:
        print_authority_metadata(om, "OEM Metadata")
    print_hash_entries(ht, algo[1] or 48)
    roots = []
    for lbl, sig, cert in regions:
        if sig or cert:
            roots.append(print_authority_signing(lbl, sig, cert))
    return [r for r in roots if r]

# hash table segment - version 5 (dual authority, no metadata)
def parse_v5(seg):
    _res, ver, qss, qcs, image_size, hts, _r4, oss, _r5, ocs = struct.unpack_from('<IIIIIIIIII', seg, 0)
    section("Hash Table Segment Header")
    field("Version", ver)
    field("Image Size", f"{image_size} (Size of data following Hash Table Segment Header)")
    field("Hash Table Size", f"{hts} (bytes)")
    field("QTI Signature Size", f"{qss} (bytes)")
    field("QTI Certificate Chain Size", f"{qcs} (bytes)")
    field("OEM Signature Size", f"{oss} (bytes)")
    field("OEM Certificate Chain Size", f"{ocs} (bytes)")
    o = 40
    ht = seg[o:o + hts]; o += hts
    qsig = seg[o:o + qss]; o += qss
    qcert = seg[o:o + qcs]; o += qcs
    osig = seg[o:o + oss]; o += oss
    ocert = seg[o:o + ocs]; o += ocs
    entry_sz = 32 if hts % 32 == 0 else 48
    print_hash_entries(ht, entry_sz)
    roots = []
    for lbl, sig, cert in (("QTI", qsig, qcert), ("OEM", osig, ocert)):
        if sig or cert:
            roots.append(print_authority_signing(lbl, sig, cert))
    return [r for r in roots if r]

# hash table segment - version 6 (v5 layout + qti/oem metadata sizes)
def parse_v6(seg):
    (_res, ver, qss, qcs, image_size, hts, _r4, oss, _r5, ocs,
     qms, oms) = struct.unpack_from('<IIIIIIIIIIII', seg, 0)
    section("Hash Table Segment Header")
    field("Version", ver)
    field("Image Size", f"{image_size} (Size of data following Hash Table Segment Header)")
    field("Hash Table Size", f"{hts} (bytes)")
    field("QTI Metadata Size", f"{qms} (bytes)")
    field("OEM Metadata Size", f"{oms} (bytes)")
    field("QTI Signature Size", f"{qss} (bytes)")
    field("QTI Certificate Chain Size", f"{qcs} (bytes)")
    field("OEM Signature Size", f"{oss} (bytes)")
    field("OEM Certificate Chain Size", f"{ocs} (bytes)")
    o = 48 + qms + oms                        # v6 metadata format differs; skip its bytes
    ht = seg[o:o + hts]; o += hts
    qsig = seg[o:o + qss]; o += qss
    qcert = seg[o:o + qcs]; o += qcs
    osig = seg[o:o + oss]; o += oss
    ocert = seg[o:o + ocs]; o += ocs
    print_hash_entries(ht, 48 if hts % 48 == 0 else 32)
    roots = []
    for lbl, sig, cert in (("QTI", qsig, qcert), ("OEM", osig, ocert)):
        if sig or cert:
            roots.append(print_authority_signing(lbl, sig, cert))
    return [r for r in roots if r]

def print_hash_entries(ht, entry_sz):
    section("Hash Table Entries")
    print(f"  {'Idx':<6} Hash\n  {'-'*80}")
    for i in range(len(ht) // entry_sz if entry_sz else 0):
        print(f"  {i:<6} 0x{ht[i*entry_sz:(i+1)*entry_sz].hex()}")

def print_authority_signing(authority, sig, cert_region, show_ou=False):
    certs = parse_certs(cert_region)
    attest, cas, root = classify_chain(certs)

    section(f"{authority} Signature Properties")
    sig_properties(sig, attest['info'] if attest else {})

    section(f"{authority} Certificate Chain Properties")
    field("Total Number of Certificates", len(certs))
    field("Number of Attest Certificates", 1 if attest else 0)
    field("Number of CA Certificates", len(cas))
    field("Number of Root Certificates", 1 if root else 0)

    if attest:
        section(f"{authority} Attest Certificate Properties")
        cert_role_properties(attest)
        if show_ou and attest['info']['ou']:
            section(f"{authority} Attestation Certificate OU Fields")
            for name, val in attest['info']['ou']:
                field(name, "0x" + val)
    for ca in cas:
        section(f"{authority} CA Certificate Properties")
        cert_role_properties(ca)
    if root:
        section(f"{authority} Root Certificate Properties")
        # root cert hash = the OEM_PK_HASH the device fuses/compares
        field("Root Certificate Hash (SHA256)", "0x" + hashlib.sha256(root['der']).hexdigest())
        field("Root Certificate Hash (SHA384)", "0x" + hashlib.sha384(root['der']).hexdigest())
        cert_role_properties(root)
    return {'authority': authority, 'certs': certs, 'root': root}

# x509 chain details (full subject/issuer/validity + pk hashes)
def print_cert_chains(all_roots, verbose):
    if not any(r['certs'] for r in all_roots):
        return
    section("Certificate Chains (X.509 details)")
    for r in all_roots:
        print(f"\n  {BOLD}{r['authority']} chain{RESET}")
        for cert in _order_chain(r['certs']):
            info = cert['info']
            role = "Root CA" if info['subject'] == info['issuer'] else "Cert"
            print(f"    {BOLD}[{role}]{RESET} @ 0x{cert['offset']:x}")
            print(f"      Subject : {info.get('subject')}")
            print(f"      Issuer  : {info.get('issuer')}")
            print(f"      Validity: {info.get('not_before')} ~ {info.get('not_after')}")
            print(f"      Sig Alg : {info.get('sig_alg')}")
            if info['subject'] == info['issuer'] or verbose >= 1:
                print(f"      {BOLD}Cert-DER SHA256 (OEM_PK_HASH):{RESET} {c(GREEN, hashlib.sha256(cert['der']).hexdigest())}")
                print(f"      {BOLD}Cert-DER SHA384 (OEM_PK_HASH):{RESET} {c(GREEN, hashlib.sha384(cert['der']).hexdigest())}")
                pk256, pk384 = _pubkey_hashes(cert['der'])
                if pk256:
                    print(f"      {DIM}SPKI SHA256 (pubkey only): {pk256}{RESET}")
                if pk384:
                    print(f"      {DIM}SPKI SHA384 (pubkey only): {pk384}{RESET}")
            if verbose >= 2:
                hexdump(cert['der'][:64], base=cert['offset'])

def _order_chain(certs):
    attest, cas, root = classify_chain(certs)
    ordered = ([root] if root else []) + cas + ([attest] if attest and attest is not root else [])
    return ordered + [x for x in certs if x not in ordered]

def _pubkey_hashes(der):
    try:
        with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
            f.write(der); t1 = f.name
        pem = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', t1, '-pubkey', '-noout'],
                             capture_output=True, text=True, timeout=8)
        os.unlink(t1)
        if pem.returncode != 0:
            return None, None
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False, mode='w') as f:
            f.write(pem.stdout); t2 = f.name
        dr = subprocess.run(['openssl', 'pkey', '-pubin', '-in', t2, '-outform', 'DER'],
                            capture_output=True, timeout=8)
        os.unlink(t2)
        if dr.returncode != 0:
            return None, None
        return hashlib.sha256(dr.stdout).hexdigest(), hashlib.sha384(dr.stdout).hexdigest()
    except Exception:
        return None, None

# tme segment (apdp / debug policy): nested tlv -> json, same as sectools --inspect
TME_LABEL = {'SvcDebugPolicy': 'OEM DPR', 'SvcRomPatch': 'SLC'}

def tme_tlv(buf):
    # walk tag(u16) len(u16) value(len)
    o = 0
    while o + 4 <= len(buf):
        tag = buf[o] | buf[o + 1] << 8
        ln = buf[o + 2] | buf[o + 3] << 8
        if o + 4 + ln > len(buf):
            break
        yield tag, bytes(buf[o + 4:o + 4 + ln])
        o += 4 + ln

_POS_SIZE = {'data_short': 2, 'data_byte': 1, 'reserve1': 1, 'reserve2': 2, 'reserve3': 3, 'reserve4': 4}

def tme_prim(tag, typ, val):
    # render a leaf value
    if typ in ('byteArray', 'data_byteArray') or typ.startswith('reserve'):
        return "0x" + val.hex()
    iv = int.from_bytes(val, 'little')
    enum = TME_ENUMS.get(tag)
    if enum:
        et, vals = enum
        if et == 'mask':
            return [vals[b] for b in sorted(vals) if b and (iv & b) == b]
        return vals.get(iv, "0x%x" % iv)
    if TME_TAGS.get(tag, ('', ''))[0] == 'CertificateVersion':
        return iv
    return "0x%0*x" % (len(val) * 2, iv)

def tme_body(tag_id, buf):
    # svc commands: leading positional cmd fields (data_*/reserve*) then tlv children
    out = {}
    o = 0
    for cid in TME_RELATIONS.get(tag_id, []):
        cname, ctype = TME_TAGS.get(cid, (f"0x{cid:04x}", ""))
        sz = _POS_SIZE.get(ctype)
        if sz is None:
            break
        out[cname] = tme_prim(cid, ctype, buf[o:o + sz])
        o += sz
    for t, v in tme_tlv(buf[o:]):
        out[TME_TAGS.get(t, (f"0x{t:04x}", ""))[0]] = tme_value(t, v)
    return out

def tme_maparray(buf):
    # repeated element: fields concatenated, new element when a field tag repeats
    elems, cur = [], {}
    for t, v in tme_tlv(buf):
        name = TME_TAGS.get(t, (f"0x{t:04x}", ""))[0]
        if name in cur:
            elems.append(cur); cur = {}
        cur[name] = tme_value(t, v)
    if cur:
        elems.append(cur)
    return elems

def tme_value(tag, val):
    # decode a tag value by its grammar type
    typ = TME_TAGS.get(tag, (f"0x{tag:04x}", "byteArray"))[1]
    if typ == 'map':
        return tme_body(tag, val)
    if typ == 'mapArray':
        return tme_maparray(val)
    if typ == 'intArray':
        return ["0x%08x" % int.from_bytes(val[i:i + 4], 'little') for i in range(0, len(val), 4)]
    return tme_prim(tag, typ, val)

def is_tme_segment(data):
    if len(data) < 4:
        return False
    tag = data[0] | data[1] << 8
    return tag in TME_TAGS and TME_TAGS[tag][0].startswith('Svc')

def print_tme_segment(seg, profiles=None):
    objs = list(tme_tlv(seg))
    section("TME Segment Properties")
    field("Number of TME Objects", len(objs))
    for i, (tag, val) in enumerate(objs, 1):
        name = TME_TAGS.get(tag, (f"0x{tag:04x}", ""))[0]
        field(f"#{i}. {TME_LABEL.get(name, name)} size", 4 + len(val))
    for i, (tag, val) in enumerate(objs, 1):
        name = TME_TAGS.get(tag, (f"0x{tag:04x}", ""))[0]
        section(f"#{i}. {TME_LABEL.get(name, name)} Details")
        obj = {name: tme_value(tag, val)}
        print(json.dumps(_flatten_chipid(obj), indent=4))
        print_tme_augmented(obj, profiles)

# level-2: decode debug vectors to named options using a security profile
# (tag_name, description, profile vector kind, show Value line)
_VEC_BLOCKS = [
    ('DebugVector', 'The Debug Options enabled by the DPR:', 'debug_vector', True),
    ('DebugIPScanDumpPolicyVector', 'The IP Scan Dump Debug Options enabled by the DPR:', 'ip_scan_dump_policy_vector', False),
    ('DebugMemDumpPolicyVector', 'The Memory Dump Debug Options enabled by the DPR:', 'mem_dump_policy_vector', False),
    ('DebugQADDumpPolicyVector', 'The QAD Dump Policy Options enabled by the DPR:', 'qad_dump_policy_vector', False),
    ('DebugRTQADDumpPolicyVector', 'The Runtime QAD Dump Policy Options enabled by the DPR:', 'rt_qad_dump_policy_vector', False),
]

# built-in debug-vector tables per soc hw version, extracted from qualcomm security
# profiles. bit meanings differ per soc, so this is keyed by soc; used when no
# --security-profile is given. pass --security-profile <xml> for other socs.
DEFAULT_DEBUG_OPTIONS = {
    '0xa00c': {
        'debug_vector': [
            ('2', 'SECURE_BOOT_DISABLE', 'Enable SECURE_BOOT_DISABLE feature.'),
            ('6', 'TIC_REENABLE', 'Enable TIC_REENABLE feature.'),
            ('11', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('12', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('13', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('14', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('15', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('16', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('17', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('19', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('20', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('21', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('22', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('23', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('24', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('27', 'APB2JTAG_REENABLE', 'Enable APB2JTAG_REENABLE feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('30', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('31', 'LPC', 'Enable LPC (LPC Debug features).'),
            ('32', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('33', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('36', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('37', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('38', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('39', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('40', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('41', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('42', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('43', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('44', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('45', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('46', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('47', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('48', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('49', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('50', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('51', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('52', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('53', 'DDRSS_SCANDUMP_REENABLE', 'Enable DDRSS_SCANDUMP_REENABLE feature.'),
            ('54', 'DEBUGBUS_DISABLE_REENABLE', 'Enable DEBUGBUS_DISABLE_REENABLE feature.'),
            ('55', 'DCC_DISABLE_REENABLE', 'Enable DCC_DISABLE_REENABLE feature.'),
            ('56', 'EUD_DISABLE_REENABLE', 'Enable EUD_DISABLE_REENABLE feature.'),
            ('57', 'SMMU_SCAN_DUMP_REENABLE', 'Enable SMMU_SCAN_DUMP_REENABLE feature.'),
            ('58', 'SP_DISABLE_REENABLE', 'Enable SP_DISABLE_REENABLE feature.'),
            ('59', 'SEC_BOOT_GPIO', 'Enable SEC_BOOT_GPIO feature.'),
        ],
    },
    '0xa012': {
        'debug_vector': [
            ('2', 'SECURE_BOOT_DISABLE', 'Enable SECURE_BOOT_DISABLE feature.'),
            ('4', 'SOCCP_DBGEN', 'Enable SOCCP_DBGEN (SOCCP Mission Mode Invasive Debug).'),
            ('5', 'SOCCP_NIDEN', 'Enable SOCCP_NIDEN (SOCCP Mission Mode Non-Invasive Debug).'),
            ('6', 'TIC_REENABLE', 'Enable TIC_REENABLE feature.'),
            ('7', 'SOCCP_CRASHDBG_DBGEN', 'Enable SOCCP_CRASHDBG_DBGEN (SOCCP Debug Workload Invasive Debug).'),
            ('8', 'NCC_MICRO_DBGEN', 'Enable NCC_MICRO_DBGEN (NCC Invasive Debug).'),
            ('9', 'NCC_MICRO_NIDEN', 'Enable NCC_MICRO_NIDEN (NCC Non-Invasive Debug).'),
            ('10', 'CMSR_SW_MODE_REENABLE', 'Enable CMSR_SW_MODE debugging.'),
            ('11', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('12', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('13', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('14', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('15', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('16', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('17', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('19', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('20', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('21', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('22', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('23', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('24', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('25', 'DDRSS_MACH9_FUSE_BIST_REENABLE', 'Reenable the DDRSS_MACH9_FUSE_BIST feature.'),
            ('26', 'DDRSS_MACH9_FUSE_ECC_SYNC_UNCORR_DATA_REENABLE', 'Reenable the DDRSS_MACH9_FUSE_ECC_SYNC_UNCORR_DATA feature.'),
            ('27', 'APB2JTAG_REENABLE', 'Reenable the APB2JTAG feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('30', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('31', 'LPC', 'Enable LPC (LPC Debug features).'),
            ('32', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('33', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('36', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('37', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('38', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('39', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('40', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('41', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('42', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('43', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('44', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('45', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('46', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('47', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('48', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('49', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('50', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('51', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('52', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('53', 'DDRSS_SCANDUMP_REENABLE', 'Enable DDRSS_SCANDUMP_REENABLE feature.'),
            ('54', 'DEBUGBUS_DISABLE_REENABLE', 'Enable DEBUGBUS_DISABLE_REENABLE feature.'),
            ('55', 'DCC_DISABLE_REENABLE', 'Enable DCC_DISABLE_REENABLE feature.'),
            ('56', 'EUD_DISABLE_REENABLE', 'Reenable the EUD feature.'),
            ('57', 'SMMU_SCAN_DUMP_REENABLE', 'Reenable the SMMU_SCAN_DUMP feature.'),
            ('58', 'SP_DISABLE_REENABLE', 'Reenable the SP feature.'),
            ('59', 'SEC_BOOT_GPIO', 'Enable SEC_BOOT_GPIO feature.'),
        ],
        'ip_scan_dump_policy_vector': [
            ('0', 'SMMU-UNENCRYPTED', 'Enable SMMU Scandump unencrypted.'),
            ('1', 'SMMU-ENCRYPTED', 'Enable SMMU Scandump encrypted.'),
            ('2', 'GPU-UNENCRYPTED', 'Enable GPU Scandump unencrypted.'),
            ('3', 'GPU-ENCRYPTED', 'Enable GPU Scandump encrypted.'),
            ('4', 'UBWCP-UNENCRYPTED', 'Enable UBWC-P Scandump unencrypted.'),
            ('5', 'UBWCP-ENCRYPTED', 'Enable UBWC-P Scandump encrypted.'),
        ],
        'qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
        ],
    },
    '0xa01b': {
        'debug_vector': [
            ('0', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('1', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('2', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('3', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('4', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('5', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('6', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('8', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('9', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('10', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('11', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('12', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('13', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('14', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('15', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('16', 'SOCCP_DBGEN', 'Enable SOCCP_DBGEN (SOCCP Mission Mode Invasive Debug).'),
            ('17', 'SOCCP_NIDEN', 'Enable SOCCP_NIDEN (SOCCP Mission Mode Non-Invasive Debug).'),
            ('18', 'SOCCP_CRASHDBG_DBGEN', 'Enable SOCCP_CRASHDBG_DBGEN (SOCCP Debug Workload Invasive Debug).'),
            ('19', 'GPU_SCANDUMP_REENABLE', 'Reenable the GPU_SCANDUMP feature.'),
            ('20', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('21', 'DDRSS_SCANDUMP_REENABLE', 'Reenable the DDRSS_SCANDUMP feature.'),
            ('22', 'SMMU_SCANDUMP_REENABLE', 'Reenable the SMMU_SCANDUMP feature.'),
            ('23', 'APB2JTAG_REENABLE', 'Reenable the APB2JTAG feature.'),
            ('24', 'LPC', 'Enable LPC (LPC Debug features).'),
            ('25', 'DEBUGBUS_REENABLE', 'Reenable the DEBUGBUS feature.'),
            ('26', 'DCC_REENABLE', 'Reenable the DCC feature.'),
            ('27', 'EUD_REENABLE', 'Reenable the EUD feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('30', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('31', 'NCC_MICRO_DBGEN', 'Enable NCC_MICRO_DBGEN (NCC Invasive Debug).'),
            ('32', 'NCC_MICRO_NIDEN', 'Enable NCC_MICRO_NIDEN (NCC Non-Invasive Debug).'),
            ('33', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('34', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('35', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('36', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('37', 'MSS_SCALAR_TRUSTED_DBGEN', 'Enable MSS_SCALAR_TRUSTED_DBGEN (Modem SCALAR Trusted Invasive Debug).'),
            ('38', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('39', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('40', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('41', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('42', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('43', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('44', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('45', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('46', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('47', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('48', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('49', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('50', 'PDP_DBGEN', 'Enable PDP_DBGEN (PDP Invasive Debug).'),
            ('51', 'PDP_NIDEN', 'Enable PDP_NIDEN (PDP Non-Invasive Debug).'),
            ('52', 'EVA_DBGEN', 'Enable EVA_DBGEN (EVA Invasive Debug).'),
            ('53', 'EVA_NIDEN', 'Enable EVA_NIDEN (EVA Non-Invasive Debug).'),
        ],
        'ip_scan_dump_policy_vector': [
            ('0', 'SMMU-UNENCRYPTED', 'Enable SMMU Scandump unencrypted.'),
            ('1', 'SMMU-ENCRYPTED', 'Enable SMMU Scandump encrypted.'),
            ('2', 'GPU-UNENCRYPTED', 'Enable GPU Scandump unencrypted.'),
            ('3', 'GPU-ENCRYPTED', 'Enable GPU Scandump encrypted.'),
            ('6', 'DDRSS-UNENCRYPTED', 'Enable DDRSS Scandump unencrypted.'),
            ('7', 'DDRSS-ENCRYPTED', 'Enable DDRSS Scandump encrypted.'),
        ],
        'qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
        ],
    },
    '0xa022': {  # molokai / SM8845
        'debug_vector': [
            ('0', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('1', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('2', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('3', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('4', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('5', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('6', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('8', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('9', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('10', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('11', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('12', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('13', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('14', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('15', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('16', 'SOCCP_DBGEN', 'Enable SOCCP_DBGEN (SOCCP Mission Mode Invasive Debug).'),
            ('17', 'SOCCP_NIDEN', 'Enable SOCCP_NIDEN (SOCCP Mission Mode Non-Invasive Debug).'),
            ('18', 'SOCCP_CRASHDBG_DBGEN', 'Enable SOCCP_CRASHDBG_DBGEN (SOCCP Debug Workload Invasive Debug).'),
            ('19', 'GPU_SCANDUMP_REENABLE', 'Reenable the GPU_SCANDUMP feature.'),
            ('20', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('21', 'DDRSS_SCANDUMP_REENABLE', 'Reenable the DDRSS_SCANDUMP feature.'),
            ('22', 'SMMU_SCANDUMP_REENABLE', 'Reenable the SMMU_SCANDUMP feature.'),
            ('23', 'APB2JTAG_REENABLE', 'Reenable the APB2JTAG feature.'),
            ('24', 'LPC', 'Enable LPC (LPC Debug features).'),
            ('25', 'DEBUGBUS_REENABLE', 'Reenable the DEBUGBUS feature.'),
            ('26', 'DCC_REENABLE', 'Reenable the DCC feature.'),
            ('27', 'EUD_REENABLE', 'Reenable the EUD feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('30', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('31', 'NCC_MICRO_DBGEN', 'Enable NCC_MICRO_DBGEN (NCC Invasive Debug).'),
            ('32', 'NCC_MICRO_NIDEN', 'Enable NCC_MICRO_NIDEN (NCC Non-Invasive Debug).'),
            ('33', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('34', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('35', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('36', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('37', 'MSS_SCALAR_TRUSTED_DBGEN', 'Enable MSS_SCALAR_TRUSTED_DBGEN (Modem SCALAR Trusted Invasive Debug).'),
            ('38', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('39', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('40', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('41', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('42', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('43', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('44', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('45', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('46', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('47', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('48', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('49', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('50', 'PDP_DBGEN', 'Enable PDP_DBGEN (PDP Invasive Debug).'),
            ('51', 'PDP_NIDEN', 'Enable PDP_NIDEN (PDP Non-Invasive Debug).'),
            ('52', 'EVA_DBGEN', 'Enable EVA_DBGEN (EVA Invasive Debug).'),
            ('53', 'EVA_NIDEN', 'Enable EVA_NIDEN (EVA Non-Invasive Debug).'),
            ('54', 'WPSS_DBGEN', 'Enable WPSS_DBGEN (WPSS Invasive Debug).'),
            ('55', 'WPSS_NIDEN', 'Enable WPSS_NIDEN (WPSS Non-Invasive Debug).'),
        ],
        'ip_scan_dump_policy_vector': [
            ('0', 'SMMU-UNENCRYPTED', 'Enable SMMU Scandump unencrypted.'),
            ('1', 'SMMU-ENCRYPTED', 'Enable SMMU Scandump encrypted.'),
            ('2', 'GPU-UNENCRYPTED', 'Enable GPU Scandump unencrypted.'),
            ('3', 'GPU-ENCRYPTED', 'Enable GPU Scandump encrypted.'),
            ('6', 'DDRSS-UNENCRYPTED', 'Enable DDRSS Scandump unencrypted.'),
            ('7', 'DDRSS-ENCRYPTED', 'Enable DDRSS Scandump encrypted.'),
        ],
        'qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
        ],
    },
    '0xa003': {  # kailua / SM8550
        'debug_vector': [
            ('2', 'SECURE_BOOT_DISABLE', 'Enable SECURE_BOOT_DISABLE feature.'),
            ('6', 'TIC_REENABLE', 'Enable TIC_REENABLE feature.'),
            ('11', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('12', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('13', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('14', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('15', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('16', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('17', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('18', 'SHRM_NIDEN', 'Enable SHRM_NIDEN (SHRM Non-Invasive Debug).'),
            ('19', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('20', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('21', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('22', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('23', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('24', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('27', 'APB2JTAG_REENABLE', 'Enable APB2JTAG_REENABLE feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('30', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('32', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('33', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('36', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('37', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('38', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('39', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('40', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('41', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('42', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('43', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('44', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('45', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('46', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('47', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('48', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('49', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('50', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('51', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('52', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('53', 'DDRSS_SCANDUMP_REENABLE', 'Enable DDRSS_SCANDUMP_REENABLE feature.'),
            ('54', 'DEBUGBUS_DISABLE_REENABLE', 'Enable DEBUGBUS_DISABLE_REENABLE feature.'),
            ('55', 'DCC_DISABLE_REENABLE', 'Enable DCC_DISABLE_REENABLE feature.'),
            ('56', 'EUD_DISABLE_REENABLE', 'Enable EUD_DISABLE_REENABLE feature.'),
            ('57', 'SMMU_SCAN_DUMP_REENABLE', 'Enable SMMU_SCAN_DUMP_REENABLE feature.'),
            ('58', 'SP_DISABLE_REENABLE', 'Enable SP_DISABLE_REENABLE feature.'),
        ],
    },
    '0xa02a': {  # maili / SM8950
        'debug_vector': [
            ('0', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('1', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('2', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('3', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('4', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('5', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('6', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('7', 'SHRM_NIDEN', 'Enable SHRM_NIDEN (SHRM Non-Invasive Debug).'),
            ('8', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('9', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('10', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('11', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('12', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('13', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('14', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('15', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('16', 'SOCCP_DBGEN', 'Enable SOCCP_DBGEN (SOCCP Mission Mode Invasive Debug).'),
            ('17', 'SOCCP_NIDEN', 'Enable SOCCP_NIDEN (SOCCP Mission Mode Non-Invasive Debug).'),
            ('20', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('21', 'MSTR_SCANDUMP_REENABLE', 'Reenable the primary SCANDUMP control.'),
            ('22', 'MSTR_MEMDUMP_REENABLE', 'Reenable the primary MEMDUMP control.'),
            ('23', 'APB2JTAG_REENABLE', 'Reenable the APB2JTAG feature.'),
            ('24', 'LPC', 'Enable LPC (LPC Debug features).'),
            ('25', 'DEBUGBUS_REENABLE', 'Reenable the DEBUGBUS feature.'),
            ('26', 'DCC_REENABLE', 'Reenable the DCC feature.'),
            ('27', 'EUD_REENABLE', 'Reenable the EUD feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('30', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('31', 'NCC_MICRO_DBGEN', 'Enable NCC_MICRO_DBGEN (NCC Invasive Debug).'),
            ('32', 'NCC_MICRO_NIDEN', 'Enable NCC_MICRO_NIDEN (NCC Non-Invasive Debug).'),
            ('33', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('34', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('35', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('36', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('37', 'MSS_SCALAR_TRUSTED_DBGEN', 'Enable MSS_SCALAR_TRUSTED_DBGEN (Modem SCALAR Trusted Invasive Debug).'),
            ('38', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('39', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('40', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('41', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('42', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('43', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('44', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('45', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('46', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('47', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('48', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('49', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('50', 'PDP_DBGEN', 'Enable PDP_DBGEN (PDP Invasive Debug).'),
            ('51', 'PDP_NIDEN', 'Enable PDP_NIDEN (PDP Non-Invasive Debug).'),
            ('52', 'EVA_DBGEN', 'Enable EVA_DBGEN (EVA Invasive Debug).'),
            ('53', 'EVA_NIDEN', 'Enable EVA_NIDEN (EVA Non-Invasive Debug).'),
            ('54', 'WPSS_DBGEN', 'Enable WPSS_DBGEN (WPSS Invasive Debug).'),
            ('55', 'WPSS_NIDEN', 'Enable WPSS_NIDEN (WPSS Non-Invasive Debug).'),
            ('56', 'QECP_DBGEN', 'Enable QECP_DBGEN (QECP Invasive Debug).'),
            ('57', 'QECP_NIDEN', 'Enable QECP_NIDEN (QECP Non-Invasive Debug).'),
        ],
        'ip_scan_dump_policy_vector': [
            ('0', 'GPU-UNENCRYPTED', 'Enable GPU Scandump unencrypted.'),
            ('1', 'GPU-ENCRYPTED', 'Enable GPU Scandump encrypted.'),
            ('2', 'DDRSS-UNENCRYPTED', 'Enable DDRSS Scandump unencrypted.'),
            ('3', 'DDRSS-ENCRYPTED', 'Enable DDRSS Scandump encrypted.'),
            ('4', 'SMMU-UNENCRYPTED', 'Enable SMMU Scandump unencrypted.'),
            ('5', 'SMMU-ENCRYPTED', 'Enable SMMU Scandump encrypted.'),
        ],
        'mem_dump_policy_vector': [
            ('0', 'GPU-UNENCRYPTED', 'Enable GPU Memdump unencrypted.'),
            ('1', 'GPU-ENCRYPTED', 'Enable GPU Memdump encrypted.'),
        ],
        'qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
            ('24', 'QECP-DEBUG-UNENCRYPTED', 'Enable QECP Data Capture Dump unencrypted.'),
            ('25', 'QECP-DEBUG-ENCRYPTED', 'Enable QECP Capture Dump encrypted.'),
        ],
        'rt_qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
            ('24', 'QECP-DEBUG-UNENCRYPTED', 'Enable QECP Data Capture Dump unencrypted.'),
            ('25', 'QECP-DEBUG-ENCRYPTED', 'Enable QECP Capture Dump encrypted.'),
        ],
    },
    '0xa023': {  # hawi / SM8975
        'debug_vector': [
            ('0', 'TMEROM_DBGEN', 'Enable TMEROM_DBGEN (TMEROM Invasive Debug).'),
            ('1', 'TMEROM_NIDEN', 'Enable TMEROM_NIDEN (TMEROM Non-Invasive Debug).'),
            ('2', 'TMERAM_DBGEN', 'Enable TMERAM_DBGEN (TMERAM Invasive Debug).'),
            ('3', 'TMERAM_NIDEN', 'Enable TMERAM_NIDEN (TMERAM Non-Invasive Debug).'),
            ('4', 'AOP_DBGEN', 'Enable AOP_DBGEN (AOP Invasive Debug).'),
            ('5', 'AOP_NIDEN', 'Enable AOP_NIDEN (AOP Non-Invasive Debug).'),
            ('6', 'SHRM_DBGEN', 'Enable SHRM_DBGEN (SHRM Invasive Debug).'),
            ('7', 'SHRM_NIDEN', 'Enable SHRM_NIDEN (SHRM Non-Invasive Debug).'),
            ('8', 'CPUCP_DBGEN', 'Enable CPUCP_DBGEN (CPUCP Invasive Debug).'),
            ('9', 'CPUCP_NIDEN', 'Enable CPUCP_NIDEN (CPUCP Non-Invasive Debug).'),
            ('10', 'QSEE_DBGEN', 'Enable QSEE_DBGEN (QSEE/TZ/APPS Secure Invasive Debug).'),
            ('11', 'QSEE_NIDEN', 'Enable QSEE_NIDEN (QSEE/TZ/APPS Secure Non-Invasive Debug).'),
            ('12', 'APPS_DBGEN', 'Enable APPS_DBGEN (APPS Non-Secure Invasive Debug).'),
            ('13', 'APPS_NIDEN', 'Enable APPS_NIDEN (APPS Non-Secure Non-Invasive Debug).'),
            ('14', 'DAP_DBGEN', 'Enable DAP_DBGEN (DAP Invasive Debug).'),
            ('15', 'DAP_NIDEN', 'Enable DAP_NIDEN (DAP Non-Invasive Debug).'),
            ('16', 'SOCCP_DBGEN', 'Enable SOCCP_DBGEN (SOCCP Mission Mode Invasive Debug).'),
            ('17', 'SOCCP_NIDEN', 'Enable SOCCP_NIDEN (SOCCP Mission Mode Non-Invasive Debug).'),
            ('20', 'APPS_SCANDUMP_REENABLE', 'Enable APPS_SCANDUMP_REENABLE feature.'),
            ('21', 'MSTR_SCANDUMP_REENABLE', 'Reenable the primary SCANDUMP control.'),
            ('22', 'MSTR_MEMDUMP_REENABLE', 'Reenable the primary MEMDUMP control.'),
            ('23', 'APB2JTAG_REENABLE', 'Reenable the APB2JTAG feature.'),
            ('24', 'LPC', 'Enable LPC (LPC Debug features).'),
            ('25', 'DEBUGBUS_REENABLE', 'Reenable the DEBUGBUS feature.'),
            ('26', 'DCC_REENABLE', 'Reenable the DCC feature.'),
            ('27', 'EUD_REENABLE', 'Reenable the EUD feature.'),
            ('28', 'GPU_PRIVATE_DBGEN', 'Enable GPU_PRIVATE_DBGEN (GPU_PRIVATE Invasive Debug).'),
            ('29', 'GPU_DBGEN', 'Enable GPU_DBGEN (GPU Invasive Debug).'),
            ('30', 'GPU_NIDEN', 'Enable GPU_NIDEN (GPU Non-Invasive Debug).'),
            ('31', 'NCC_MICRO_DBGEN', 'Enable NCC_MICRO_DBGEN (NCC Invasive Debug).'),
            ('32', 'NCC_MICRO_NIDEN', 'Enable NCC_MICRO_NIDEN (NCC Non-Invasive Debug).'),
            ('33', 'MSS_VECTOR_DBGEN', 'Enable MSS_VECTOR_DBGEN (Modem VECTOR Invasive Debug).'),
            ('34', 'MSS_VECTOR_NIDEN', 'Enable MSS_VECTOR_NIDEN (Modem VECTOR Non-Invasive Debug).'),
            ('35', 'MSS_SCALAR_DBGEN', 'Enable MSS_SCALAR_DBGEN (Modem SCALAR Invasive Debug).'),
            ('36', 'MSS_SCALAR_NIDEN', 'Enable MSS_SCALAR_NIDEN (Modem SCALAR Non-Invasive Debug).'),
            ('37', 'MSS_SCALAR_TRUSTED_DBGEN', 'Enable MSS_SCALAR_TRUSTED_DBGEN (Modem SCALAR Trusted Invasive Debug).'),
            ('38', 'TITAN_DBGEN', 'Enable TITAN_DBGEN (TITAN/Camera Invasive Debug).'),
            ('39', 'TITAN_NIDEN', 'Enable TITAN_NIDEN (TITAN/Camera Non-Invasive Debug).'),
            ('40', 'LPASS_DBGEN', 'Enable LPASS_DBGEN (LPASS/ADSP/Audio Invasive Debug).'),
            ('41', 'LPASS_NIDEN', 'Enable LPASS_NIDEN (LPASS/ADSP/Audio Non-Invasive Debug).'),
            ('42', 'TURING_DBGEN', 'Enable TURING_DBGEN (TURING/CDSP/Compute Invasive Debug).'),
            ('43', 'TURING_NIDEN', 'Enable TURING_NIDEN (TURING/CDSP/Compute Non-Invasive Debug).'),
            ('44', 'IRIS_DBGEN', 'Enable IRIS_DBGEN (IRIS/Video Invasive Debug).'),
            ('45', 'IRIS_NIDEN', 'Enable IRIS_NIDEN (IRIS/Video Non-Invasive Debug).'),
            ('46', 'MDSS_DBGEN', 'Enable MDSS_DBGEN (MDSS/Display Invasive Debug).'),
            ('47', 'MDSS_NIDEN', 'Enable MDSS_NIDEN (MDSS/Display Non-Invasive Debug).'),
            ('48', 'DDRSS_DBGEN', 'Enable DDRSS_DBGEN (DDRSS Invasive Debug).'),
            ('49', 'DDRSS_NIDEN', 'Enable DDRSS_NIDEN (DDRSS Non-Invasive Debug).'),
            ('50', 'PDP_DBGEN', 'Enable PDP_DBGEN (PDP Invasive Debug).'),
            ('51', 'PDP_NIDEN', 'Enable PDP_NIDEN (PDP Non-Invasive Debug).'),
            ('52', 'EVA_DBGEN', 'Enable EVA_DBGEN (EVA Invasive Debug).'),
            ('53', 'EVA_NIDEN', 'Enable EVA_NIDEN (EVA Non-Invasive Debug).'),
            ('56', 'QECP_DBGEN', 'Enable QECP_DBGEN (QECP Invasive Debug).'),
            ('57', 'QECP_NIDEN', 'Enable QECP_NIDEN (QECP Non-Invasive Debug).'),
        ],
        'ip_scan_dump_policy_vector': [
            ('0', 'GPU-UNENCRYPTED', 'Enable GPU Scandump unencrypted.'),
            ('1', 'GPU-ENCRYPTED', 'Enable GPU Scandump encrypted.'),
            ('2', 'DDRSS-UNENCRYPTED', 'Enable DDRSS Scandump unencrypted.'),
            ('3', 'DDRSS-ENCRYPTED', 'Enable DDRSS Scandump encrypted.'),
            ('4', 'SMMU-UNENCRYPTED', 'Enable SMMU Scandump unencrypted.'),
            ('5', 'SMMU-ENCRYPTED', 'Enable SMMU Scandump encrypted.'),
        ],
        'mem_dump_policy_vector': [
            ('0', 'GPU-UNENCRYPTED', 'Enable GPU Memdump unencrypted.'),
            ('1', 'GPU-ENCRYPTED', 'Enable GPU Memdump encrypted.'),
        ],
        'qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
            ('24', 'QECP-DEBUG-UNENCRYPTED', 'Enable QECP Data Capture Dump unencrypted.'),
            ('25', 'QECP-DEBUG-ENCRYPTED', 'Enable QECP Capture Dump encrypted.'),
        ],
        'rt_qad_dump_policy_vector': [
            ('0', 'APPS-NON-SECURE-UNENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump unencrypted.'),
            ('1', 'APPS-NON-SECURE-ENCRYPTED', 'Enable APPS Non-Secure Data Capture Dump encrypted.'),
            ('2', 'APPS-SECURE-UNENCRYPTED', 'Enable APPS Secure Data Capture Dump unencrypted.'),
            ('3', 'APPS-SECURE-ENCRYPTED', 'Enable APPS Secure Data Capture Dump encrypted.'),
            ('8', 'DEBUG-UNENCRYPTED', 'Enable DEBUG Data Capture Dump unencrypted.'),
            ('9', 'DEBUG-ENCRYPTED', 'Enable DEBUG Data Capture Dump encrypted.'),
            ('10', 'AOP-UNENCRYPTED', 'Enable AOP Data Capture Dump unencrypted.'),
            ('11', 'AOP-ENCRYPTED', 'Enable AOP Data Capture Dump encrypted.'),
            ('12', 'MODEM-UNENCRYPTED', 'Enable Modem Data Capture Dump unencrypted.'),
            ('13', 'MODEM-ENCRYPTED', 'Enable Modem Data Capture Dump encrypted.'),
            ('24', 'QECP-DEBUG-UNENCRYPTED', 'Enable QECP Data Capture Dump unencrypted.'),
            ('25', 'QECP-DEBUG-ENCRYPTED', 'Enable QECP Capture Dump encrypted.'),
        ],
    },
}

def load_security_profiles(paths):
    # soc hw version (lower) -> {vector kind: [(bit spec, id, description)]}
    kinds = {'debug_vector': 'debug_vector_option', 'ip_scan_dump_policy_vector': 'scan_dump_ip',
             'mem_dump_policy_vector': 'mem_dump_type', 'qad_dump_policy_vector': 'qad',
             'rt_qad_dump_policy_vector': 'qad'}
    lname = lambda e: e.tag.split('}')[-1]
    prof = {}
    for p in paths or []:
        try:
            root = ET.parse(p).getroot()
        except Exception:
            continue
        socs = []
        for e in root.iter():
            if lname(e) == 'soc_hw_versions':
                socs = [(v.text or '').strip().lower() for v in e if lname(v) == 'value' and v.text]
                break
        data = {}
        for kind, item in kinds.items():
            opts = []
            for cont in root.iter():
                if lname(cont) != kind:
                    continue
                for o in cont.iter():
                    if lname(o) != item:
                        continue
                    bit = desc = None
                    for ch in o:
                        if lname(ch) in ('bit', 'bits'):
                            bit = (ch.text or '').strip()
                        elif lname(ch) == 'description':
                            desc = (ch.text or '').strip()
                    if bit is not None:
                        opts.append((bit, o.get('id'), desc or ''))
            if opts:
                data[kind] = opts
        fuse_rows = []
        for fr in root.iter():
            if lname(fr) != 'fuse_region':
                continue
            rid = fr.get('id')
            for row in fr:
                if lname(row) != 'fuse_row':
                    continue
                try:
                    addr = int(row.get('address'), 16)
                except (TypeError, ValueError):
                    continue
                fuses = []
                for fu in row:
                    if lname(fu) != 'fuse':
                        continue
                    nm = bt = rc = None
                    for ch in fu:
                        t = lname(ch)
                        if t == 'name': nm = (ch.text or '').strip()
                        elif t == 'bits': bt = (ch.text or '').strip()
                        elif t == 'recommendation': rc = (ch.text or '').strip()
                    if nm and bt is not None:
                        fuses.append((nm, bt, rc))
                if fuses:
                    fuse_rows.append((addr, rid, fuses))
        if fuse_rows:
            data['fuse_table'] = fuse_rows
        for soc in socs:
            prof[soc] = data
    return prof

def _tme_find(d, name):
    # first value for key `name` anywhere in the object tree
    if isinstance(d, dict):
        for k, v in d.items():
            if k == name:
                return v
            r = _tme_find(v, name)
            if r is not None:
                return r
    elif isinstance(d, list):
        for x in d:
            r = _tme_find(x, name)
            if r is not None:
                return r
    return None

def _vec_rows(hexval, options):
    # little-endian value; one row per set bit
    h = hexval[2:] if hexval.startswith('0x') else hexval
    v = int.from_bytes(bytes.fromhex(h), 'little')
    bmap = {}
    for spec, oid, desc in options:
        rng = range(int(spec.split('-')[0]), int(spec.split('-')[1]) + 1) if '-' in spec else [int(spec)]
        for b in rng:
            bmap[b] = (oid, desc)
    rows = [('Bit', 'ID', 'Description')]
    for b in range(v.bit_length()):
        if v >> b & 1:
            oid, desc = bmap.get(b, ('UNKNOWN', 'Not specified in the provided Security Profile.'))
            rows.append((str(b), oid, desc))
    return rows if len(rows) > 1 else None

def _render_table(rows):
    cols = range(len(rows[0]))
    w = [max(len(str(r[i])) for r in rows) for i in cols]
    line = lambda r: "|" + "|".join(" " + str(r[i]).ljust(w[i] + 1) + " " for i in cols) + "|"
    sep = "|" + "|".join("-" * (w[i] + 3) for i in cols) + "|"
    return "\n".join([line(rows[0]), sep] + [line(r) for r in rows[1:]])

def print_tme_augmented(obj, profiles):
    # decode debug vectors to named options; use a provided profile if it matches
    # this soc, else the built-in table so it works without --security-profile
    soc = _tme_find(obj, 'SocHardwareVersion')
    if not isinstance(soc, str):
        return
    key = soc[:-4].lower()
    data = (profiles or {}).get(key)
    builtin = not data
    if not data:
        data = DEFAULT_DEBUG_OPTIONS.get(key)   # per-soc built-in table
    if not data:
        return
    out = []
    for tag, desc, kind, show_val in _VEC_BLOCKS:
        opts = data.get(kind)
        val = _tme_find(obj, tag)
        if not opts or not isinstance(val, str):
            continue
        rows = _vec_rows(val, opts)
        if not rows:
            continue
        block = "\n" + desc + (f"\nValue: {val}" if show_val else "") + "\n" + _render_table(rows)
        out.append(block)
    if not out:
        return
    if builtin:
        print(f"\n{DIM}(debug options from built-in table; pass --security-profile <xml> for the exact per-soc set){RESET}")
    for block in out:
        print(block)


def _flatten_chipid(o):
    # list ChipUniqueIdentifier fields flat instead of as a nested struct
    if isinstance(o, dict):
        new = {}
        for k, v in o.items():
            if k == 'ChipUniqueIdentifier' and isinstance(v, dict):
                for kk, vv in v.items():
                    new[f'ChipUniqueIdentifier {kk}'] = _flatten_chipid(vv)
            else:
                new[k] = _flatten_chipid(v)
        return new
    if isinstance(o, list):
        return [_flatten_chipid(x) for x in o]
    return o

# multi-image segment (MULT): a signed elf whose load segment holds an image list
MULTI_IMAGE_MAGIC = b'MULT'
MI_NUM_RESERVED = 32
MI_HASH_ALGO = {2: 'SHA256', 3: 'SHA384'}
MI_HASH_LEN = {2: 32, 3: 48}

def is_multi_image_segment(seg):
    return len(seg) >= 4 and seg[:4] == MULTI_IMAGE_MAGIC

def print_multi_image_segment(seg):
    fmt = '<4sI' + 'Q' * MI_NUM_RESERVED + 'II'
    hdr_size = struct.calcsize(fmt)
    vals = struct.unpack_from(fmt, seg, 0)
    version, num_entries, algo = vals[1], vals[-2], vals[-1]
    section("Multi-Image Segment Header")
    field("Magic", vals[0].decode('latin1'))
    field("Version", version)
    field("Number of Image Entries", num_entries)
    field("Hash Algorithm", MI_HASH_ALGO.get(algo, algo))
    if num_entries:
        hlen = MI_HASH_LEN.get(algo, 48)
        efmt = f'<II{hlen}s'
        esz = struct.calcsize(efmt)
        rows = [('Index', 'Software ID', 'Secondary Software ID', 'Hash')]
        off = hdr_size
        for i in range(num_entries):
            sw, ssw, h = struct.unpack_from(efmt, seg, off)
            rows.append((str(i), hexs(sw), hexs(ssw), h.hex()))
            off += esz
        section("Multi-Image Segment Entries")
        print(_render_table(rows))

# sec_dat / SEC-ELF fuse image (magic ca51723b 296f122a). region/operation names
# and struct layouts are taken from sectools common/parser/sec_dat.
SECDAT_MAGIC1, SECDAT_MAGIC2 = 0x3B7251CA, 0x2A126F29
SECDAT_SEG_TYPE = {0: 'Efuse', 1: 'Key Provision'}
SECDAT_REGION_V1 = {0: 'OEM_SEC_BOOT', 1: 'OEM_PK_HASH', 2: 'SEC_HW_KEY', 3: 'OEM_CONFIG',
    4: 'READ_WRITE_PERM', 5: 'SPARE_REG19', 6: 'GENERAL', 7: 'FEC_EN', 8: 'ANTI_ROLLBACK_2',
    9: 'ANTI_ROLLBACK_3', 10: 'PK_HASH1', 11: 'IMAGE_ENCR_KEY1', 12: 'OEM_SECURE', 13: 'MRC_2_0',
    14: 'OEM_SPARE', 15: 'OEM_PRODUCT_SEED', 16: 'ANTI_ROLLBACK_1', 17: 'TME_RW_PERM',
    18: 'TME_FEC_EN', 19: 'TME_OEM', 20: 'RFA_CALIBRATION_OEM', 21: 'RFA_SW_OEM', 22: 'QC_SPARE'}
SECDAT_OP_V1 = {0: 'BLOW', 1: 'VERIFY_MASK', 2: 'BLOW_RANDOM'}
SECDAT_REGION_V3 = {0: 'OEM_SEC_BOOT', 1: 'OEM_PK_HASH', 2: 'SEC_HW_KEY', 3: 'OEM_CONFIG',
    4: 'READ_PERM', 5: 'WRITE_PERM', 6: 'FEC_EN', 7: 'ANTI_ROLLBACK', 8: 'IMAGE_ENCR_KEY',
    9: 'MRC_2_0', 10: 'OEM_SPARE', 11: 'OEM_PRODUCT_SEED', 12: 'TME_RW_PERM', 13: 'TME_FEC_EN',
    14: 'TME_OEM', 15: 'TME_SPARE', 16: 'OEM_SECURE'}
SECDAT_OP_V3 = {0: 'BLOW', 1: 'BLOW_RANDOM'}

# built-in fuse-blow tables per soc (address, region, [(name, bits, recommendation)]),
# TME socs generated from qualcomm security profiles' <fuse_blowing> regions;
# msm8996 from the QFPROM Programming Reference (raw addr = 0x70000 + row*8).
# lets a SEC-ELF / sec.dat fuse file be decoded to the named fuses it blows.
FUSE_TABLES = {
    '0xa01b': [  # kaanapali / SM8850
        (0x221c0090, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', '0'),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', '1'),
            ('DISALLOW_TME_DEBUG', '2', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', '1'),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', '1'),
            ('ACTIVATE_SECURITY_POLICY', '11', '1'),
            ('OEM_DEVICE_LCS', '17:16', '0x3'),
            ('AUTH_EN', '33', '1'),
            ('PK_HASH_IN_FUSE', '34', '1'),
            ('USE_SERIAL_NUM', '35', None),
            ('ROM_PK_HASH_IDX', '39:36', '0x0'),
        ]),
        (0x221c0098, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', '1'),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '6', '1'),
            ('READ_PERMISSIONS_WRITE_DISABLE', '7', '1'),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '8', '1'),
            ('DEBUG_DISABLE_WRITE_DISABLE', '9', '1'),
            ('OEM_CONFIG_WRITE_DISABLE', '14', '1'),
            ('MRC_HASH_WRITE_DISABLE', '27', '1'),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '28', '1'),
            ('OEM_SPARE_0_WRITE_DISABLE', '34', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '35', None),
        ]),
        (0x221c00a0, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '28', '1'),
        ]),
        (0x221c00a8, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '27', '1'),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '28', '1'),
        ]),
        (0x221c00b0, 'DEBUG_DISABLE', [
            ('AOP_NIDEN_DISABLE', '5', '1'),
            ('CPUCP_NIDEN_DISABLE', '9', '1'),
            ('QSEE_DBGEN_DISABLE', '10', '1'),
            ('QSEE_NIDEN_DISABLE', '11', '1'),
            ('APPS_DBGEN_DISABLE', '12', '1'),
            ('APPS_NIDEN_DISABLE', '13', '1'),
            ('DAP_DBGEN_DISABLE', '14', '1'),
            ('DAP_NIDEN_DISABLE', '15', '1'),
            ('SOCCP_DBGEN_DISABLE', '16', '1'),
            ('SOCCP_NIDEN_DISABLE', '17', '1'),
            ('APPS_SCANDUMP_DISABLE', '20', '1'),
            ('DDRSS_SCANDUMP_DISABLE', '21', '1'),
            ('SMMU_SCANDUMP_DISABLE', '22', '1'),
            ('DEBUGBUS_DISABLE', '25', '1'),
            ('DCC_DISABLE', '26', '1'),
            ('GPU_DBGEN_DISABLE', '29', '1'),
            ('GPU_NIDEN_DISABLE', '30', '1'),
            ('MSS_SCALAR_DBGEN_DISABLE', '35', '1'),
            ('MSS_SCALAR_NIDEN_DISABLE', '36', '1'),
            ('TITAN_DBGEN_DISABLE', '38', '1'),
            ('TITAN_NIDEN_DISABLE', '39', '1'),
            ('LPASS_DBGEN_DISABLE', '40', '1'),
            ('LPASS_NIDEN_DISABLE', '41', '1'),
            ('TURING_DBGEN_DISABLE', '42', '1'),
            ('TURING_NIDEN_DISABLE', '43', '1'),
            ('IRIS_DBGEN_DISABLE', '44', '1'),
            ('IRIS_NIDEN_DISABLE', '45', '1'),
            ('MDSS_DBGEN_DISABLE', '46', '1'),
            ('MDSS_NIDEN_DISABLE', '47', '1'),
            ('DDRSS_NIDEN_DISABLE', '49', '1'),
            ('PDP_NIDEN_DISABLE', '51', '1'),
            ('EVA_DBGEN_DISABLE', '52', '1'),
            ('EVA_NIDEN_DISABLE', '53', '1'),
        ]),
        (0x221c0158, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('SPI_CLK_BOOT_FREQ', '11:10', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('ROOT_CERT_TOTAL_NUM', '18:17', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('SP_DISABLE', '27', None),
            ('DEBUG_POLICY_DISABLE', '28', '0'),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
        ]),
        (0x221c0160, 'OEM_CONFIG', [
            ('SPU_ENABLEMENT_OPTION', '2:1', '0x0'),
            ('SP_FIPS_ENABLE', '3', None),
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('SP_FIPS_OVERRIDE', '6', None),
            ('SPU_IAR_ENABLED', '10', None),
            ('SP_ARI_TEST_MODE_FEATURE_ENABLE', '16', None),
            ('SP_ARI_SUSPENSION_FEATURE_ENABLE', '17', None),
            ('EKU_ENFORCEMENT_EN', '30', '1'),
            ('OEM_HW_ID', '47:32', 'OEM_VALUE'),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0168, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', '0xf'),
            ('PERIPH_CTRL', '40', None),
        ]),
        (0x221c0840, 'MRC_HASH', [
            ('MRC_HASH', '55:0', 'OEM_VALUE'),
            ('FEC_204', '62:56', None),
        ]),
        (0x221c0848, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_205', '62:56', None),
        ]),
        (0x221c0850, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_206', '62:56', None),
        ]),
        (0x221c0858, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_207', '62:56', None),
        ]),
        (0x221c0860, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_208', '62:56', None),
        ]),
        (0x221c0868, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_209', '62:56', None),
        ]),
        (0x221c0870, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_210', '62:56', None),
        ]),
        (0x221c0878, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_211', '62:56', None),
        ]),
        (0x221c0880, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_212', '62:56', None),
        ]),
        (0x221c0888, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_213', '62:56', None),
        ]),
        (0x221c0890, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_214', '62:56', None),
        ]),
        (0x221c0898, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_215', '62:56', None),
        ]),
        (0x221c08a0, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', 'OEM_VALUE'),
            ('FEC_216', '62:56', None),
        ]),
        (0x221c1958, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1960, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1968, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1970, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c1978, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    '0xa022': [  # molokai / SM8845
        (0x221c0090, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', '0'),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', '1'),
            ('DISALLOW_TME_DEBUG', '2', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', '1'),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', '1'),
            ('ACTIVATE_SECURITY_POLICY', '11', '1'),
            ('OEM_DEVICE_LCS', '17:16', '0x3'),
            ('AUTH_EN', '33', '1'),
            ('PK_HASH_IN_FUSE', '34', '1'),
            ('USE_SERIAL_NUM', '35', None),
        ]),
        (0x221c0098, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', '1'),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '6', '1'),
            ('READ_PERMISSIONS_WRITE_DISABLE', '7', '1'),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '8', '1'),
            ('DEBUG_DISABLE_WRITE_DISABLE', '9', '1'),
            ('OEM_CONFIG_WRITE_DISABLE', '14', '1'),
            ('MRC_HASH_WRITE_DISABLE', '27', '1'),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '28', '1'),
            ('OEM_SPARE_0_WRITE_DISABLE', '34', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '35', None),
        ]),
        (0x221c00a0, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '28', '1'),
        ]),
        (0x221c00a8, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '27', '1'),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '28', '1'),
        ]),
        (0x221c00b0, 'DEBUG_DISABLE', [
            ('AOP_NIDEN_DISABLE', '5', '1'),
            ('CPUCP_NIDEN_DISABLE', '9', '1'),
            ('QSEE_DBGEN_DISABLE', '10', '1'),
            ('QSEE_NIDEN_DISABLE', '11', '1'),
            ('APPS_DBGEN_DISABLE', '12', '1'),
            ('APPS_NIDEN_DISABLE', '13', '1'),
            ('DAP_DBGEN_DISABLE', '14', '1'),
            ('DAP_NIDEN_DISABLE', '15', '1'),
            ('SOCCP_DBGEN_DISABLE', '16', '1'),
            ('SOCCP_NIDEN_DISABLE', '17', '1'),
            ('APPS_SCANDUMP_DISABLE', '20', '1'),
            ('DDRSS_SCANDUMP_DISABLE', '21', '1'),
            ('SMMU_SCANDUMP_DISABLE', '22', '1'),
            ('DEBUGBUS_DISABLE', '25', '1'),
            ('DCC_DISABLE', '26', '1'),
            ('GPU_DBGEN_DISABLE', '29', '1'),
            ('GPU_NIDEN_DISABLE', '30', '1'),
            ('MSS_SCALAR_DBGEN_DISABLE', '35', '1'),
            ('MSS_SCALAR_NIDEN_DISABLE', '36', '1'),
            ('TITAN_DBGEN_DISABLE', '38', '1'),
            ('TITAN_NIDEN_DISABLE', '39', '1'),
            ('LPASS_DBGEN_DISABLE', '40', '1'),
            ('LPASS_NIDEN_DISABLE', '41', '1'),
            ('TURING_DBGEN_DISABLE', '42', '1'),
            ('TURING_NIDEN_DISABLE', '43', '1'),
            ('IRIS_DBGEN_DISABLE', '44', '1'),
            ('IRIS_NIDEN_DISABLE', '45', '1'),
            ('MDSS_DBGEN_DISABLE', '46', '1'),
            ('MDSS_NIDEN_DISABLE', '47', '1'),
            ('DDRSS_NIDEN_DISABLE', '49', '1'),
            ('PDP_NIDEN_DISABLE', '51', '1'),
            ('EVA_DBGEN_DISABLE', '52', '1'),
            ('EVA_NIDEN_DISABLE', '53', '1'),
            ('WPSS_DBGEN_DISABLE', '54', '0'),
            ('WPSS_NIDEN_DISABLE', '55', '0'),
        ]),
        (0x221c0158, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('SPI_CLK_BOOT_FREQ', '11:10', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('ROOT_CERT_TOTAL_NUM', '18:17', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('DEBUG_POLICY_DISABLE', '28', '0'),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
        ]),
        (0x221c0160, 'OEM_CONFIG', [
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('EKU_ENFORCEMENT_EN', '30', '1'),
            ('OEM_HW_ID', '47:32', 'OEM_VALUE'),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0168, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', '0xf'),
            ('PERIPH_CTRL', '40', None),
        ]),
        (0x221c0840, 'MRC_HASH', [
            ('MRC_HASH', '55:0', 'OEM_VALUE'),
            ('FEC_204', '62:56', None),
        ]),
        (0x221c0848, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_205', '62:56', None),
        ]),
        (0x221c0850, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_206', '62:56', None),
        ]),
        (0x221c0858, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_207', '62:56', None),
        ]),
        (0x221c0860, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_208', '62:56', None),
        ]),
        (0x221c0868, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_209', '62:56', None),
        ]),
        (0x221c0870, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_210', '62:56', None),
        ]),
        (0x221c0878, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_211', '62:56', None),
        ]),
        (0x221c0880, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_212', '62:56', None),
        ]),
        (0x221c0888, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_213', '62:56', None),
        ]),
        (0x221c0890, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_214', '62:56', None),
        ]),
        (0x221c0898, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_215', '62:56', None),
        ]),
        (0x221c08a0, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', 'OEM_VALUE'),
            ('FEC_216', '62:56', None),
        ]),
        (0x221c1958, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1960, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1968, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1970, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c1978, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    '0xa003': [  # kailua / SM8550
        (0x221c0080, 'MRC', [
            ('OEM_ROOT_CERT_ACTIVATION_LIST_0', '17', None),
            ('OEM_ROOT_CERT_ACTIVATION_LIST_1', '18', None),
            ('OEM_ROOT_CERT_ACTIVATION_LIST_2', '19', None),
            ('OEM_ROOT_CERT_ACTIVATION_LIST_3', '20', None),
            ('OEM_ROOT_CERT_REVOCATION_LIST_0', '21', None),
            ('OEM_ROOT_CERT_REVOCATION_LIST_1', '22', None),
            ('OEM_ROOT_CERT_REVOCATION_LIST_2', '23', None),
            ('OEM_ROOT_CERT_REVOCATION_LIST_3', '24', None),
        ]),
        (0x221c0090, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', None),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', None),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', None),
            ('ACTIVATE_SECURITY_POLICY', '11', None),
            ('OEM_DEVICE_LCS', '17:16', None),
            ('AUTH_EN', '33', None),
            ('PK_HASH_IN_FUSE', '34', None),
            ('USE_SERIAL_NUM', '35', None),
            ('ROM_PK_HASH_IDX', '39:36', None),
        ]),
        (0x221c00e0, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', None),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '7', None),
            ('READ_PERMISSIONS_WRITE_DISABLE', '8', None),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '9', None),
            ('DEBUG_DISABLE_WRITE_DISABLE', '10', None),
            ('OEM_CONFIG_WRITE_DISABLE', '12', None),
            ('ANTI_ROLLBACK_WRITE_DISABLE', '16', None),
            ('MRC_HASH_WRITE_DISABLE', '24', None),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '25', None),
            ('OEM_SPARE_0_WRITE_DISABLE', '31', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '32', None),
        ]),
        (0x221c00e8, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '25', None),
        ]),
        (0x221c00f0, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '24', None),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '25', None),
        ]),
        (0x221c00f8, 'DEBUG_DISABLE', [
            ('SHRM_DBGEN_DISABLE', '6', None),
            ('SHRM_NIDEN_DISABLE', '7', None),
            ('CPUCP_DBGEN_DISABLE', '8', None),
            ('CPUCP_NIDEN_DISABLE', '9', None),
            ('QSEE_DBGEN_DISABLE', '12', None),
            ('QSEE_NIDEN_DISABLE', '13', None),
            ('APPS_DBGEN_DISABLE', '32', None),
            ('APPS_NIDEN_DISABLE', '33', None),
            ('MSS_SCALAR_DBGEN_DISABLE', '34', None),
            ('MSS_SCALAR_NIDEN_DISABLE', '35', None),
            ('TITAN_DBGEN_DISABLE', '38', None),
            ('TITAN_NIDEN_DISABLE', '39', None),
            ('LPASS_DBGEN_DISABLE', '40', None),
            ('LPASS_NIDEN_DISABLE', '41', None),
            ('TURING_DBGEN_DISABLE', '42', None),
            ('TURING_NIDEN_DISABLE', '43', None),
            ('IRIS_DBGEN_DISABLE', '44', None),
            ('IRIS_NIDEN_DISABLE', '45', None),
            ('MDSS_DBGEN_DISABLE', '46', None),
            ('MDSS_NIDEN_DISABLE', '47', None),
            ('DDRSS_DBGEN_DISABLE', '48', None),
            ('DDRSS_NIDEN_DISABLE', '49', None),
            ('GPU_DBGEN_DISABLE', '50', None),
            ('GPU_NIDEN_DISABLE', '51', None),
            ('DAP_DBGEN_DISABLE', '52', None),
            ('DAP_NIDEN_DISABLE', '53', None),
            ('APPS_SCANDUMP_DISABLE', '54', None),
            ('DDRSS_SCANDUMP_DISABLE', '55', None),
            ('DEBUGBUS_DISABLE', '56', None),
            ('DCC_DISABLE', '57', None),
            ('SMMU_SCANDUMP_DISABLE', '59', None),
        ]),
        (0x221c0110, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('PBL_QSPI_BOOT_EDL_ENABLED', '10', None),
            ('SPI_CLK_BOOT_FREQ', '11', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('ROOT_CERT_TOTAL_NUM', '18:17', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('SP_DISABLE', '27', None),
            ('DEBUG_POLICY_DISABLE', '28', None),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
        ]),
        (0x221c0118, 'OEM_CONFIG', [
            ('SPU_ENABLEMENT_OPTION', '2:1', None),
            ('SP_FIPS_ENABLE', '3', None),
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('SP_FIPS_OVERRIDE', '6', None),
            ('SPU_IAR_ENABLED', '10', None),
            ('SPARE_REG0_SECURE', '12', None),
            ('SPARE_REG1_SECURE', '13', None),
            ('SP_ARI_TEST_MODE_FEATURE_ENABLE', '16', None),
            ('SP_ARI_SUSPENSION_FEATURE_ENABLE', '17', None),
            ('EKU_ENFORCEMENT_EN', '30', None),
            ('DISABLE_RSA', '31', None),
            ('OEM_HW_ID', '47:32', None),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0120, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', None),
        ]),
        (0x221c0250, 'ANTI_ROLLBACK', [
            ('PERIPH_CTRL', '2', None),
        ]),
        (0x221c0420, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_124', '62:56', None),
        ]),
        (0x221c0428, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_125', '62:56', None),
        ]),
        (0x221c0430, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_126', '62:56', None),
        ]),
        (0x221c0438, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_127', '62:56', None),
        ]),
        (0x221c0440, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_128', '62:56', None),
        ]),
        (0x221c0448, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_129', '62:56', None),
        ]),
        (0x221c0450, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_130', '62:56', None),
        ]),
        (0x221c0458, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_131', '62:56', None),
        ]),
        (0x221c0460, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_132', '62:56', None),
        ]),
        (0x221c0468, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_133', '62:56', None),
        ]),
        (0x221c0470, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', None),
            ('FEC_128', '62:56', None),
        ]),
        (0x221c0478, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', None),
            ('FEC_129', '62:56', None),
        ]),
        (0x221c0480, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', None),
            ('FEC_130', '62:56', None),
        ]),
        (0x221c0fa0, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c0fa8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c0fb0, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c0fb8, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    '0xa00c': [  # lanai / SM8650
        (0x221c0090, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', None),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', None),
            ('DISALLOW_TME_DEBUG', '2', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', None),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', None),
            ('ACTIVATE_SECURITY_POLICY', '11', None),
            ('OEM_DEVICE_LCS', '17:16', None),
            ('AUTH_EN', '33', None),
            ('PK_HASH_IN_FUSE', '34', None),
            ('USE_SERIAL_NUM', '35', None),
            ('ROM_PK_HASH_IDX', '39:36', None),
        ]),
        (0x221c00d8, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', None),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '7', None),
            ('READ_PERMISSIONS_WRITE_DISABLE', '8', None),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '9', None),
            ('DEBUG_DISABLE_WRITE_DISABLE', '10', None),
            ('OEM_CONFIG_WRITE_DISABLE', '12', None),
            ('MRC_HASH_WRITE_DISABLE', '27', None),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '28', None),
            ('OEM_SPARE_0_WRITE_DISABLE', '34', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '35', None),
        ]),
        (0x221c00e0, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '28', None),
        ]),
        (0x221c00e8, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '27', None),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '28', None),
        ]),
        (0x221c00f0, 'DEBUG_DISABLE', [
            ('SHRM_DBGEN_DISABLE', '6', None),
            ('CPUCP_DBGEN_DISABLE', '8', None),
            ('CPUCP_NIDEN_DISABLE', '9', None),
            ('QSEE_DBGEN_DISABLE', '12', None),
            ('QSEE_NIDEN_DISABLE', '13', None),
            ('APPS_DBGEN_DISABLE', '32', None),
            ('APPS_NIDEN_DISABLE', '33', None),
            ('MSS_SCALAR_DBGEN_DISABLE', '34', None),
            ('MSS_SCALAR_NIDEN_DISABLE', '35', None),
            ('TITAN_DBGEN_DISABLE', '38', None),
            ('TITAN_NIDEN_DISABLE', '39', None),
            ('LPASS_DBGEN_DISABLE', '40', None),
            ('LPASS_NIDEN_DISABLE', '41', None),
            ('TURING_DBGEN_DISABLE', '42', None),
            ('TURING_NIDEN_DISABLE', '43', None),
            ('IRIS_DBGEN_DISABLE', '44', None),
            ('IRIS_NIDEN_DISABLE', '45', None),
            ('MDSS_DBGEN_DISABLE', '46', None),
            ('MDSS_NIDEN_DISABLE', '47', None),
            ('DDRSS_DBGEN_DISABLE', '48', None),
            ('DDRSS_NIDEN_DISABLE', '49', None),
            ('GPU_DBGEN_DISABLE', '50', None),
            ('GPU_NIDEN_DISABLE', '51', None),
            ('DAP_DBGEN_DISABLE', '52', None),
            ('DAP_NIDEN_DISABLE', '53', None),
            ('APPS_SCANDUMP_DISABLE', '54', None),
            ('DDRSS_SCANDUMP_DISABLE', '55', None),
            ('DEBUGBUS_DISABLE', '56', None),
            ('DCC_DISABLE', '57', None),
            ('SMMU_SCANDUMP_DISABLE', '59', None),
        ]),
        (0x221c0108, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('SPI_CLK_BOOT_FREQ', '11:10', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('ROOT_CERT_TOTAL_NUM', '18:17', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('SP_DISABLE', '27', None),
            ('DEBUG_POLICY_DISABLE', '28', None),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
        ]),
        (0x221c0110, 'OEM_CONFIG', [
            ('SPU_ENABLEMENT_OPTION', '2:1', None),
            ('SP_FIPS_ENABLE', '3', None),
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('SP_FIPS_OVERRIDE', '6', None),
            ('SPU_IAR_ENABLED', '10', None),
            ('SP_ARI_TEST_MODE_FEATURE_ENABLE', '16', None),
            ('SP_ARI_SUSPENSION_FEATURE_ENABLE', '17', None),
            ('EKU_ENFORCEMENT_EN', '30', None),
            ('OEM_HW_ID', '47:32', None),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0118, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', None),
            ('PERIPH_CTRL', '40', None),
        ]),
        (0x221c0660, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_204', '62:56', None),
        ]),
        (0x221c0668, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_205', '62:56', None),
        ]),
        (0x221c0670, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_206', '62:56', None),
        ]),
        (0x221c0678, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_207', '62:56', None),
        ]),
        (0x221c0680, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_208', '62:56', None),
        ]),
        (0x221c0688, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_209', '62:56', None),
        ]),
        (0x221c0690, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_210', '62:56', None),
        ]),
        (0x221c0698, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_211', '62:56', None),
        ]),
        (0x221c06a0, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_212', '62:56', None),
        ]),
        (0x221c06a8, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_213', '62:56', None),
        ]),
        (0x221c06b0, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', None),
            ('FEC_214', '62:56', None),
        ]),
        (0x221c06b8, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', None),
            ('FEC_215', '62:56', None),
        ]),
        (0x221c06c0, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', None),
            ('FEC_216', '62:56', None),
        ]),
        (0x221c1340, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1348, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1350, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c1358, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    '0xa012': [  # pakala / SM8750
        (0x221c0090, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', '0'),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', '1'),
            ('DISALLOW_TME_DEBUG', '2', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', '1'),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', '1'),
            ('ACTIVATE_SECURITY_POLICY', '11', '1'),
            ('OEM_DEVICE_LCS', '17:16', '0x3'),
            ('AUTH_EN', '33', '1'),
            ('PK_HASH_IN_FUSE', '34', '1'),
            ('USE_SERIAL_NUM', '35', None),
            ('ROM_PK_HASH_IDX', '39:36', '0x0'),
        ]),
        (0x221c0098, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', '1'),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '6', '1'),
            ('READ_PERMISSIONS_WRITE_DISABLE', '7', '1'),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '8', '1'),
            ('DEBUG_DISABLE_WRITE_DISABLE', '9', '1'),
            ('OEM_CONFIG_WRITE_DISABLE', '14', '1'),
            ('MRC_HASH_WRITE_DISABLE', '26', '1'),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '27', '1'),
            ('OEM_SPARE_0_WRITE_DISABLE', '33', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '34', None),
        ]),
        (0x221c00a0, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '27', '1'),
        ]),
        (0x221c0150, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('SPI_CLK_BOOT_FREQ', '11:10', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('ROOT_CERT_TOTAL_NUM', '18:17', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('SP_DISABLE', '27', None),
            ('DEBUG_POLICY_DISABLE', '28', '0'),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
        ]),
        (0x221c0158, 'OEM_CONFIG', [
            ('SPU_ENABLEMENT_OPTION', '2:1', '0x0'),
            ('SP_FIPS_ENABLE', '3', None),
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('SP_FIPS_OVERRIDE', '6', None),
            ('SPU_IAR_ENABLED', '10', None),
            ('SP_ARI_TEST_MODE_FEATURE_ENABLE', '16', None),
            ('SP_ARI_SUSPENSION_FEATURE_ENABLE', '17', None),
            ('EKU_ENFORCEMENT_EN', '30', '1'),
            ('OEM_HW_ID', '47:32', 'OEM_VALUE'),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0160, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', '0xf'),
            ('PERIPH_CTRL', '40', None),
        ]),
        (0x221c00a8, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '26', '1'),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '27', '1'),
        ]),
        (0x221c00b0, 'DEBUG_DISABLE', [
            ('CPUCP_NIDEN_DISABLE', '9', '1'),
            ('QSEE_DBGEN_DISABLE', '12', '1'),
            ('QSEE_NIDEN_DISABLE', '13', '1'),
            ('SOCCP_DBGEN_DISABLE', '21', '1'),
            ('SOCCP_NIDEN_DISABLE', '22', '1'),
            ('APPS_DBGEN_DISABLE', '32', '1'),
            ('APPS_NIDEN_DISABLE', '33', '1'),
            ('MSS_SCALAR_DBGEN_DISABLE', '34', '1'),
            ('MSS_SCALAR_NIDEN_DISABLE', '35', '1'),
            ('TITAN_DBGEN_DISABLE', '38', '1'),
            ('TITAN_NIDEN_DISABLE', '39', '1'),
            ('LPASS_DBGEN_DISABLE', '40', '1'),
            ('LPASS_NIDEN_DISABLE', '41', '1'),
            ('TURING_DBGEN_DISABLE', '42', '1'),
            ('TURING_NIDEN_DISABLE', '43', '1'),
            ('IRIS_DBGEN_DISABLE', '44', '1'),
            ('IRIS_NIDEN_DISABLE', '45', '1'),
            ('MDSS_DBGEN_DISABLE', '46', '1'),
            ('MDSS_NIDEN_DISABLE', '47', '1'),
            ('DDRSS_NIDEN_DISABLE', '49', '1'),
            ('GPU_DBGEN_DISABLE', '50', '1'),
            ('GPU_NIDEN_DISABLE', '51', '1'),
            ('DAP_DBGEN_DISABLE', '52', '1'),
            ('DAP_NIDEN_DISABLE', '53', '1'),
            ('APPS_SCANDUMP_DISABLE', '54', '1'),
            ('DDRSS_SCANDUMP_DISABLE', '55', '1'),
            ('DEBUGBUS_DISABLE', '56', '1'),
            ('DCC_DISABLE', '57', '1'),
            ('SMMU_SCANDUMP_DISABLE', '59', '1'),
        ]),
        (0x221c07b0, 'MRC_HASH', [
            ('MRC_HASH', '55:0', 'OEM_VALUE'),
            ('FEC_204', '62:56', None),
        ]),
        (0x221c07b8, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_205', '62:56', None),
        ]),
        (0x221c07c0, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_206', '62:56', None),
        ]),
        (0x221c07c8, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_207', '62:56', None),
        ]),
        (0x221c07d0, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_208', '62:56', None),
        ]),
        (0x221c07d8, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_209', '62:56', None),
        ]),
        (0x221c07e0, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_210', '62:56', None),
        ]),
        (0x221c07e8, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_211', '62:56', None),
        ]),
        (0x221c07f0, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_212', '62:56', None),
        ]),
        (0x221c07f8, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_213', '62:56', None),
        ]),
        (0x221c0800, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_214', '62:56', None),
        ]),
        (0x221c0808, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_215', '62:56', None),
        ]),
        (0x221c0810, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', 'OEM_VALUE'),
            ('FEC_216', '62:56', None),
        ]),
        (0x221c17e8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c17f0, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c17f8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c1800, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c1808, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    '0xa02a': [  # maili / SM8950
        (0x221c00a0, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', '0'),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', '1'),
            ('DISALLOW_TME_DEBUG', '2', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', '1'),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', '1'),
            ('ACTIVATE_SECURITY_POLICY', '11', '1'),
            ('OEM_DEVICE_LCS', '17:16', '0x3'),
            ('AUTH_EN', '33', '1'),
            ('PK_HASH_IN_FUSE', '34', '1'),
            ('USE_SERIAL_NUM', '35', '0'),
        ]),
        (0x221c00a8, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', '1'),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '6', '1'),
            ('READ_PERMISSIONS_WRITE_DISABLE', '7', '1'),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '8', '1'),
            ('DEBUG_DISABLE_WRITE_DISABLE', '9', '1'),
            ('OEM_CONFIG_WRITE_DISABLE', '14', '1'),
            ('MRC_HASH_WRITE_DISABLE', '28', '1'),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '29', '1'),
            ('OEM_SPARE_0_WRITE_DISABLE', '35', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '36', None),
        ]),
        (0x221c00b0, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '29', '1'),
            ('OEM_SPARE_0_READ_DISABLE', '35', '0'),
            ('OEM_SPARE_1_READ_DISABLE', '36', '0'),
        ]),
        (0x221c00b8, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '28', '1'),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '29', '1'),
        ]),
        (0x221c00c0, 'DEBUG_DISABLE', [
            ('AOP_NIDEN_DISABLE', '5', '1'),
            ('CPUCP_NIDEN_DISABLE', '9', '1'),
            ('QSEE_DBGEN_DISABLE', '10', '1'),
            ('QSEE_NIDEN_DISABLE', '11', '1'),
            ('APPS_DBGEN_DISABLE', '12', '1'),
            ('APPS_NIDEN_DISABLE', '13', '1'),
            ('DAP_DBGEN_DISABLE', '14', '1'),
            ('DAP_NIDEN_DISABLE', '15', '1'),
            ('SOCCP_DBGEN_DISABLE', '16', '1'),
            ('SOCCP_NIDEN_DISABLE', '17', '1'),
            ('APPS_SCANDUMP_DISABLE', '20', '1'),
            ('MSTR_SCANDUMP_DISABLE', '21', '1'),
            ('MSTR_MEMDUMP_DISABLE', '22', '1'),
            ('DEBUGBUS_DISABLE', '25', '1'),
            ('DCC_DISABLE', '26', '1'),
            ('GPU_DBGEN_DISABLE', '29', '1'),
            ('GPU_NIDEN_DISABLE', '30', '1'),
            ('MSS_SCALAR_DBGEN_DISABLE', '35', '1'),
            ('MSS_SCALAR_NIDEN_DISABLE', '36', '1'),
            ('MSS_SCALAR_TRUSTED_DBGEN_DISABLE', '37', '1'),
            ('TITAN_DBGEN_DISABLE', '38', '1'),
            ('TITAN_NIDEN_DISABLE', '39', '1'),
            ('LPASS_DBGEN_DISABLE', '40', '1'),
            ('LPASS_NIDEN_DISABLE', '41', '1'),
            ('TURING_DBGEN_DISABLE', '42', '1'),
            ('TURING_NIDEN_DISABLE', '43', '1'),
            ('IRIS_DBGEN_DISABLE', '44', '1'),
            ('IRIS_NIDEN_DISABLE', '45', '1'),
            ('MDSS_DBGEN_DISABLE', '46', '1'),
            ('MDSS_NIDEN_DISABLE', '47', '1'),
            ('DDRSS_NIDEN_DISABLE', '49', '1'),
            ('PDP_NIDEN_DISABLE', '51', '1'),
            ('EVA_DBGEN_DISABLE', '52', '1'),
            ('EVA_NIDEN_DISABLE', '53', '1'),
            ('WPSS_DBGEN_DISABLE', '54', '1'),
            ('WPSS_NIDEN_DISABLE', '55', '1'),
        ]),
        (0x221c0168, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('SPI_CLK_BOOT_FREQ', '11:10', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('SP_DISABLE', '27', None),
            ('DEBUG_POLICY_DISABLE', '28', '0'),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
            ('NO_OPTIONAL_LOADING_IN_PBL', '31', None),
        ]),
        (0x221c0170, 'OEM_CONFIG', [
            ('SPU_ENABLEMENT_OPTION', '2:1', '0x0'),
            ('SP_FIPS_ENABLE', '3', None),
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('SP_FIPS_OVERRIDE', '6', None),
            ('SPU_IAR_ENABLED', '10', None),
            ('KEY_DEV_ENABLE', '11', None),
            ('SP_ARI_TEST_MODE_FEATURE_ENABLE', '16', None),
            ('SP_ARI_SUSPENSION_FEATURE_ENABLE', '17', None),
            ('DEBUG_UART_BAUDRATE', '20:18', None),
            ('EKU_ENFORCEMENT_EN', '30', '1'),
            ('OEM_HW_ID', '47:32', 'OEM_VALUE'),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0178, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', '0xf'),
            ('PERIPH_CTRL', '40', None),
            ('ROOT_CERT_TOTAL_NUM', '43:41', None),
        ]),
        (0x221c0800, 'MRC_HASH', [
            ('MRC_HASH', '55:0', 'OEM_VALUE'),
            ('FEC_204', '62:56', None),
        ]),
        (0x221c0808, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_205', '62:56', None),
        ]),
        (0x221c0810, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_206', '62:56', None),
        ]),
        (0x221c0818, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_207', '62:56', None),
        ]),
        (0x221c0820, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_208', '62:56', None),
        ]),
        (0x221c0828, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_209', '62:56', None),
        ]),
        (0x221c0830, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_210', '62:56', None),
        ]),
        (0x221c0838, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_211', '62:56', None),
        ]),
        (0x221c0840, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_212', '62:56', None),
        ]),
        (0x221c0848, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_213', '62:56', None),
        ]),
        (0x221c0850, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_214', '62:56', None),
        ]),
        (0x221c0858, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_215', '62:56', None),
        ]),
        (0x221c0860, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', 'OEM_VALUE'),
            ('FEC_216', '62:56', None),
        ]),
        (0x221c19c8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c19d0, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c19d8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c19e0, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c19e8, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c19f0, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    '0xa023': [  # hawi / SM8975
        (0x221c00a0, 'OEM_SECURITY_POLICY', [
            ('DISALLOW_SOC_DEBUG', '0', '0'),
            ('ENFORCE_OEM_AUTHZ_ON_SOC_DEBUG', '1', '1'),
            ('DISALLOW_TME_DEBUG', '2', None),
            ('ENFORCE_OEM_AUTHZ_ON_FUSE_OVERRIDES', '4', '1'),
            ('ENFORCE_OEM_AUTHZ_ON_ROM_PATCH', '5', '1'),
            ('ACTIVATE_SECURITY_POLICY', '11', '1'),
            ('OEM_DEVICE_LCS', '17:16', '0x3'),
            ('AUTH_EN', '33', '1'),
            ('PK_HASH_IN_FUSE', '34', '1'),
            ('USE_SERIAL_NUM', '35', '0'),
        ]),
        (0x221c00a8, 'WRITE_PERMISSIONS', [
            ('OEM_SECURITY_POLICY_WRITE_DISABLE', '5', '1'),
            ('WRITE_PERMISSIONS_WRITE_DISABLE', '6', '1'),
            ('READ_PERMISSIONS_WRITE_DISABLE', '7', '1'),
            ('FUSE_REDUNDANCY_ENABLE_WRITE_DISABLE', '8', '1'),
            ('DEBUG_DISABLE_WRITE_DISABLE', '9', '1'),
            ('OEM_CONFIG_WRITE_DISABLE', '14', '1'),
            ('MRC_HASH_WRITE_DISABLE', '28', '1'),
            ('OEM_PRODUCT_SEED_WRITE_DISABLE', '29', '1'),
            ('OEM_SPARE_0_WRITE_DISABLE', '35', None),
            ('OEM_SPARE_1_WRITE_DISABLE', '36', None),
        ]),
        (0x221c00b0, 'READ_PERMISSIONS', [
            ('OEM_PRODUCT_SEED_READ_DISABLE', '29', '1'),
            ('OEM_SPARE_0_READ_DISABLE', '35', '0'),
            ('OEM_SPARE_1_READ_DISABLE', '36', '0'),
        ]),
        (0x221c00b8, 'FUSE_REDUNDANCY_ENABLE', [
            ('MRC_HASH_FEC_ENABLE', '28', '1'),
            ('OEM_PRODUCT_SEED_FEC_ENABLE', '29', '1'),
        ]),
        (0x221c00c0, 'DEBUG_DISABLE', [
            ('AOP_NIDEN_DISABLE', '5', '1'),
            ('CPUCP_NIDEN_DISABLE', '9', '1'),
            ('QSEE_DBGEN_DISABLE', '10', '1'),
            ('QSEE_NIDEN_DISABLE', '11', '1'),
            ('APPS_DBGEN_DISABLE', '12', '1'),
            ('APPS_NIDEN_DISABLE', '13', '1'),
            ('DAP_DBGEN_DISABLE', '14', '1'),
            ('DAP_NIDEN_DISABLE', '15', '1'),
            ('SOCCP_DBGEN_DISABLE', '16', '1'),
            ('SOCCP_NIDEN_DISABLE', '17', '1'),
            ('APPS_SCANDUMP_DISABLE', '20', '1'),
            ('MSTR_SCANDUMP_DISABLE', '21', '1'),
            ('MSTR_MEMDUMP_DISABLE', '22', '1'),
            ('DEBUGBUS_DISABLE', '25', '1'),
            ('DCC_DISABLE', '26', '1'),
            ('GPU_DBGEN_DISABLE', '29', '1'),
            ('GPU_NIDEN_DISABLE', '30', '1'),
            ('MSS_SCALAR_DBGEN_DISABLE', '35', '1'),
            ('MSS_SCALAR_NIDEN_DISABLE', '36', '1'),
            ('MSS_SCALAR_TRUSTED_DBGEN_DISABLE', '37', '1'),
            ('TITAN_DBGEN_DISABLE', '38', '1'),
            ('TITAN_NIDEN_DISABLE', '39', '1'),
            ('LPASS_DBGEN_DISABLE', '40', '1'),
            ('LPASS_NIDEN_DISABLE', '41', '1'),
            ('TURING_DBGEN_DISABLE', '42', '1'),
            ('TURING_NIDEN_DISABLE', '43', '1'),
            ('IRIS_DBGEN_DISABLE', '44', '1'),
            ('IRIS_NIDEN_DISABLE', '45', '1'),
            ('MDSS_DBGEN_DISABLE', '46', '1'),
            ('MDSS_NIDEN_DISABLE', '47', '1'),
            ('DDRSS_NIDEN_DISABLE', '49', '1'),
            ('PDP_NIDEN_DISABLE', '51', '1'),
            ('EVA_DBGEN_DISABLE', '52', '1'),
            ('EVA_NIDEN_DISABLE', '53', '1'),
        ]),
        (0x221c0168, 'OEM_CONFIG', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FORCE_USB_BOOT_GPIO_DISABLE', '3', None),
            ('SDCC_ADMA_DISABLE', '4', None),
            ('FAST_BOOT', '9:5', None),
            ('SPI_CLK_BOOT_FREQ', '11:10', None),
            ('PBL_FDL_TIMEOUT_RESET_FEATURE_ENABLE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('PBL_USB_TYPE_C_DISABLE', '16', None),
            ('QSPI_DMA_DISABLE', '19', None),
            ('USB_SS_DISABLE', '22', None),
            ('USB_PIPO_DISABLE', '23', None),
            ('SP_DISABLE', '27', None),
            ('DEBUG_POLICY_DISABLE', '28', '0'),
            ('PBL_FDL_TIMEOUT_RESET_TO_VAL', '30:29', None),
            ('NO_OPTIONAL_LOADING_IN_PBL', '31', None),
        ]),
        (0x221c0170, 'OEM_CONFIG', [
            ('SPU_ENABLEMENT_OPTION', '2:1', '0x0'),
            ('SP_FIPS_ENABLE', '3', None),
            ('TZ_SW_CRYPTO_FIPS_ENABLE', '4', None),
            ('SP_FIPS_OVERRIDE', '6', None),
            ('SPU_IAR_ENABLED', '10', None),
            ('KEY_DEV_ENABLE', '11', '0'),
            ('SP_ARI_TEST_MODE_FEATURE_ENABLE', '16', None),
            ('SP_ARI_SUSPENSION_FEATURE_ENABLE', '17', None),
            ('DEBUG_UART_BAUDRATE', '20:18', None),
            ('EKU_ENFORCEMENT_EN', '30', '1'),
            ('OEM_HW_ID', '47:32', 'OEM_VALUE'),
            ('OEM_PRODUCT_ID', '63:48', None),
        ]),
        (0x221c0178, 'OEM_CONFIG', [
            ('PERIPH_PID', '15:0', None),
            ('PERIPH_VID', '31:16', None),
            ('ANTI_ROLLBACK_FEATURE_EN', '35:32', '0xf'),
            ('PERIPH_CTRL', '40', None),
            ('ROOT_CERT_TOTAL_NUM', '43:41', None),
        ]),
        (0x221c0800, 'MRC_HASH', [
            ('MRC_HASH', '55:0', 'OEM_VALUE'),
            ('FEC_204', '62:56', None),
        ]),
        (0x221c0808, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_205', '62:56', None),
        ]),
        (0x221c0810, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_206', '62:56', None),
        ]),
        (0x221c0818, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_207', '62:56', None),
        ]),
        (0x221c0820, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_208', '62:56', None),
        ]),
        (0x221c0828, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_209', '62:56', None),
        ]),
        (0x221c0830, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_210', '62:56', None),
        ]),
        (0x221c0838, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_211', '62:56', None),
        ]),
        (0x221c0840, 'MRC_HASH', [
            ('MRC_HASH', '55:0', None),
            ('FEC_212', '62:56', None),
        ]),
        (0x221c0848, 'MRC_HASH', [
            ('MRC_HASH', '7:0', None),
            ('FEC_213', '62:56', None),
        ]),
        (0x221c0850, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_214', '62:56', None),
        ]),
        (0x221c0858, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '55:0', 'OEM_VALUE'),
            ('FEC_215', '62:56', None),
        ]),
        (0x221c0860, 'OEM_PRODUCT_SEED', [
            ('OEM_PRODUCT_SEED', '15:0', 'OEM_VALUE'),
            ('FEC_216', '62:56', None),
        ]),
        (0x221c19c8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c19d0, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c19d8, 'OEM_SPARE_0', [
            ('OEM_SPARE_0', '63:0', None),
        ]),
        (0x221c19e0, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c19e8, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
        (0x221c19f0, 'OEM_SPARE_1', [
            ('OEM_SPARE_1', '63:0', None),
        ]),
    ],
    'msm8996': [  # msm8996 / Snapdragon 820/821 (old sec.dat)
        (0x00070150, 'Read permissions', [
            ('Read permissions read disable', '3', None),
            ('Write permissions read disable', '4', None),
            ('FEC enables read disable', '5', None),
            ('Anti-rollback #1 read disable', '6', None),
            ('Anti-rollback #2 read disable', '7', None),
            ('Anti-rollback #3 read disable', '8', None),
            ('Anti-rollback #4 read disable', '9', None),
            ('OEM configuration read disable', '10', None),
            ('Public key hash 0 read disable', '12', None),
            ('OEM image encryption key read disable', '23', None),
            ('OEM secure boot read disable', '24', None),
            ('Secondary key derivation key read disable', '26', None),
            ('Image encryption key 1 read disable', '29', None),
            ('Public key hash 1 read disable', '30', None),
            ('OEM Spare 31 read disable', '31', None),
            ('OEM Spare 32 read disable', '32', None),
            ('OEM Spare 33 read disable', '33', None),
            ('OEM Spare 34 read disable', '34', None),
            ('OEM Spare 35 read disable', '35', None),
            ('OEM Spare 36 read disable', '36', None),
            ('OEM Spare 37 read disable', '37', None),
            ('OEM Spare 38 read disable', '38', None),
            ('OEM Spare 39 read disable', '39', None),
            ('OEM Spare 40 read disable', '40', None),
            ('OEM Spare 41 read disable', '41', None),
            ('OEM Spare 42 read disable', '42', None),
            ('OEM Spare 43 read disable', '43', None),
            ('OEM Spare 44 read disable', '44', None),
        ]),
        (0x00070158, 'Write permissions', [
            ('Read permissions write disable', '3', None),
            ('Write permissions write disable', '4', None),
            ('FEC enables write disable', '5', None),
            ('Anti-Rollback #1 write disable', '6', None),
            ('Anti-Rollback #2 write disable', '7', None),
            ('Anti-Rollback #3 write disable', '8', None),
            ('Anti-Rollback #4 write disable', '9', None),
            ('OEM configuration write disable', '10', None),
            ('Public key hash 0 write disable', '12', None),
            ('OEM image encryption key write disable', '23', None),
            ('OEM secure boot write disable', '24', None),
            ('Secondary key derivation key write disable', '26', None),
            ('Image encryption key 1 write disable', '29', None),
            ('Public key hash 1 write disable', '30', None),
            ('OEM Spare 31 write disable', '31', None),
            ('OEM Spare 32 write disable', '32', None),
            ('OEM Spare 33 write disable', '33', None),
            ('OEM Spare 34 write disable', '34', None),
            ('OEM Spare 35 write disable', '35', None),
            ('OEM Spare 36 write disable', '36', None),
            ('OEM Spare 37 write disable', '37', None),
            ('OEM Spare 38 write disable', '38', None),
            ('OEM Spare 39 write disable', '39', None),
            ('OEM Spare 40 write disable', '40', None),
            ('OEM Spare 41 write disable', '41', None),
            ('OEM Spare 42 write disable', '42', None),
            ('OEM Spare 43 write disable', '43', None),
            ('OEM Spare 44 write disable', '44', None),
        ]),
        (0x00070160, 'FEC enables', [
            ('OEM image encryption key FEC enable', '23', None),
            ('OEM secure boot FEC enable', '24', None),
            ('Secondary key derivation key FEC enable', '26', None),
            ('Image encryption key 1 FEC enable', '29', None),
            ('Public key hash 1 FEC enable', '30', None),
        ]),
        (0x00070168, 'Anti–rollback', [
            ('XBL0[0]', '0', None),
            ('XBL0[1]', '1', None),
            ('XBL0[2]', '2', None),
            ('XBL0[3]', '3', None),
            ('XBL0[4]', '4', None),
            ('XBL0[5]', '5', None),
            ('XBL0[6]', '6', None),
            ('XBL0[7]', '7', None),
            ('XBL0[8]', '8', None),
            ('XBL0[9]', '9', None),
            ('XBL0[10]', '10', None),
            ('XBL0[11]', '11', None),
            ('XBL0[12]', '12', None),
            ('XBL0[13]', '13', None),
            ('XBL0[14]', '14', None),
            ('XBL0[15]', '15', None),
            ('XBL0[16]', '16', None),
            ('XBL0[17]', '17', None),
            ('XBL0[18]', '18', None),
            ('XBL0[19]', '19', None),
            ('XBL0[20]', '20', None),
            ('XBL0[21]', '21', None),
            ('XBL0[22]', '22', None),
            ('XBL0[23]', '23', None),
            ('XBL0[24]', '24', None),
            ('XBL0[25]', '25', None),
            ('XBL0[26]', '26', None),
            ('XBL0[27]', '27', None),
            ('XBL0[28]', '28', None),
            ('XBL0[29]', '29', None),
            ('XBL0[30]', '30', None),
            ('XBL0[31]', '31', None),
            ('XBL1[0]', '32', None),
            ('XBL1[1]', '33', None),
            ('XBL1[2]', '34', None),
            ('XBL1[3]', '35', None),
            ('XBL1[4]', '36', None),
            ('XBL1[5]', '37', None),
            ('XBL1[6]', '38', None),
            ('XBL1[7]', '39', None),
            ('XBL1[8]', '40', None),
            ('XBL1[9]', '41', None),
            ('XBL1[10]', '42', None),
            ('XBL1[11]', '43', None),
            ('XBL1[12]', '44', None),
            ('XBL1[13]', '45', None),
            ('XBL1[14]', '46', None),
            ('XBL1[15]', '47', None),
            ('XBL1[16]', '48', None),
            ('XBL1[17]', '49', None),
            ('XBL1[18]', '50', None),
            ('XBL1[19]', '51', None),
            ('XBL1[20]', '52', None),
            ('XBL1[21]', '53', None),
            ('XBL1[22]', '54', None),
            ('XBL1[23]', '55', None),
            ('XBL1[24]', '56', None),
            ('XBL1[25]', '57', None),
            ('XBL1[26]', '58', None),
            ('XBL1[27]', '59', None),
            ('XBL1[28]', '60', None),
            ('XBL1[29]', '61', None),
            ('XBL1[30]', '62', None),
            ('XBL1[31]', '63', None),
        ]),
        (0x00070170, 'Anti–rollback', [
            ('PIL_SUBSYSTEM_31_0[0]', '0', None),
            ('PIL_SUBSYSTEM_31_0[1]', '1', None),
            ('PIL_SUBSYSTEM_31_0[2]', '2', None),
            ('PIL_SUBSYSTEM_31_0[3]', '3', None),
            ('PIL_SUBSYSTEM_31_0[4]', '4', None),
            ('PIL_SUBSYSTEM_31_0[5]', '5', None),
            ('PIL_SUBSYSTEM_31_0[6]', '6', None),
            ('PIL_SUBSYSTEM_31_0[7]', '7', None),
            ('PIL_SUBSYSTEM_31_0[8]', '8', None),
            ('PIL_SUBSYSTEM_31_0[9]', '9', None),
            ('PIL_SUBSYSTEM_31_0[10]', '10', None),
            ('PIL_SUBSYSTEM_31_0[11]', '11', None),
            ('PIL_SUBSYSTEM_31_0[12]', '12', None),
            ('PIL_SUBSYSTEM_31_0[13]', '13', None),
            ('PIL_SUBSYSTEM_31_0[14]', '14', None),
            ('PIL_SUBSYSTEM_31_0[15]', '15', None),
            ('PIL_SUBSYSTEM_31_0[16]', '16', None),
            ('PIL_SUBSYSTEM_31_0[17]', '17', None),
            ('PIL_SUBSYSTEM_31_0[18]', '18', None),
            ('PIL_SUBSYSTEM_31_0[19]', '19', None),
            ('PIL_SUBSYSTEM_31_0[20]', '20', None),
            ('PIL_SUBSYSTEM_31_0[21]', '21', None),
            ('PIL_SUBSYSTEM_31_0[22]', '22', None),
            ('PIL_SUBSYSTEM_31_0[23]', '23', None),
            ('PIL_SUBSYSTEM_31_0[24]', '24', None),
            ('PIL_SUBSYSTEM_31_0[25]', '25', None),
            ('PIL_SUBSYSTEM_31_0[26]', '26', None),
            ('PIL_SUBSYSTEM_31_0[27]', '27', None),
            ('PIL_SUBSYSTEM_31_0[28]', '28', None),
            ('PIL_SUBSYSTEM_31_0[29]', '29', None),
            ('PIL_SUBSYSTEM_31_0[30]', '30', None),
            ('PIL_SUBSYSTEM_31_0[31]', '31', None),
            ('TZ[0]', '32', None),
            ('TZ[1]', '33', None),
            ('TZ[2]', '34', None),
            ('TZ[3]', '35', None),
            ('TZ[4]', '36', None),
            ('TZ[5]', '37', None),
            ('TZ[6]', '38', None),
            ('TZ[7]', '39', None),
            ('TZ[8]', '40', None),
            ('TZ[9]', '41', None),
            ('TZ[10]', '42', None),
            ('TZ[11]', '43', None),
            ('TZ[12]', '44', None),
            ('TZ[13]', '45', None),
            ('TZ[14]', '46', None),
            ('TZ[15]', '47', None),
            ('TZ[16]', '48', None),
            ('RPM[0]', '49', None),
            ('RPM[1]', '50', None),
            ('RPM[2]', '51', None),
            ('RPM[3]', '52', None),
            ('RPM[4]', '53', None),
            ('RPM[5]', '54', None),
            ('RPM[6]', '55', None),
            ('RPM[7]', '56', None),
        ]),
        (0x00070178, 'Anti–rollback', [
            ('SAFESWITCH[0]', '0', None),
            ('SAFESWITCH[1]', '1', None),
            ('SAFESWITCH[2]', '2', None),
            ('SAFESWITCH[3]', '3', None),
            ('SAFESWITCH[4]', '4', None),
            ('SAFESWITCH[5]', '5', None),
            ('SAFESWITCH[6]', '6', None),
            ('SAFESWITCH[7]', '7', None),
            ('PIL_SUBSYSTEM_47_32[32]', '8', None),
            ('PIL_SUBSYSTEM_47_32[33]', '9', None),
            ('PIL_SUBSYSTEM_47_32[34]', '10', None),
            ('PIL_SUBSYSTEM_47_32[35]', '11', None),
            ('PIL_SUBSYSTEM_47_32[36]', '12', None),
            ('PIL_SUBSYSTEM_47_32[37]', '13', None),
            ('PIL_SUBSYSTEM_47_32[38]', '14', None),
            ('PIL_SUBSYSTEM_47_32[39]', '15', None),
            ('PIL_SUBSYSTEM_47_32[40]', '16', None),
            ('PIL_SUBSYSTEM_47_32[41]', '17', None),
            ('PIL_SUBSYSTEM_47_32[42]', '18', None),
            ('PIL_SUBSYSTEM_47_32[43]', '19', None),
            ('PIL_SUBSYSTEM_47_32[44]', '20', None),
            ('PIL_SUBSYSTEM_47_32[45]', '21', None),
            ('PIL_SUBSYSTEM_47_32[46]', '22', None),
            ('PIL_SUBSYSTEM_47_32[47]', '23', None),
            ('RPMB_KEY_PROVISIONED', '24', None),
            ('TQS_HASH_ACTIVE[0]', '25', None),
            ('TQS_HASH_ACTIVE[1]', '26', None),
            ('TQS_HASH_ACTIVE[2]', '27', None),
            ('TQS_HASH_ACTIVE[3]', '28', None),
            ('TQS_HASH_ACTIVE[4]', '29', None),
            ('HYPERVISOR[0]', '32', None),
            ('HYPERVISOR[1]', '33', None),
            ('HYPERVISOR[2]', '34', None),
            ('HYPERVISOR[3]', '35', None),
            ('HYPERVISOR[4]', '36', None),
            ('HYPERVISOR[5]', '37', None),
            ('HYPERVISOR[6]', '38', None),
            ('HYPERVISOR[7]', '39', None),
            ('HYPERVISOR[8]', '40', None),
            ('HYPERVISOR[9]', '41', None),
            ('HYPERVISOR[10]', '42', None),
            ('HYPERVISOR[11]', '43', None),
            ('DEBUG_POLICY[0]', '44', None),
            ('DEBUG_POLICY[1]', '45', None),
            ('DEBUG_POLICY[2]', '46', None),
            ('DEBUG_POLICY[3]', '47', None),
            ('DEBUG_POLICY[4]', '48', None),
            ('DEVICE_CFG[0]', '49', None),
            ('DEVICE_CFG[1]', '50', None),
            ('DEVICE_CFG[2]', '51', None),
            ('DEVICE_CFG[3]', '52', None),
            ('DEVICE_CFG[4]', '53', None),
            ('DEVICE_CFG[5]', '54', None),
            ('DEVICE_CFG[6]', '55', None),
            ('DEVICE_CFG[7]', '56', None),
            ('DEVICE_CFG[8]', '57', None),
            ('DEVICE_CFG[9]', '58', None),
            ('DEVICE_CFG[10]', '59', None),
        ]),
        (0x00070180, 'Anti–rollback', [
            ('MBA[0]', '0', None),
            ('MBA[1]', '1', None),
            ('MBA[2]', '2', None),
            ('MBA[3]', '3', None),
            ('MBA[4]', '4', None),
            ('MBA[5]', '5', None),
            ('MBA[6]', '6', None),
            ('MBA[7]', '7', None),
            ('MBA[8]', '8', None),
            ('MBA[9]', '9', None),
            ('MBA[10]', '10', None),
            ('MBA[11]', '11', None),
            ('MBA[12]', '12', None),
            ('MBA[13]', '13', None),
            ('MBA[14]', '14', None),
            ('MBA[15]', '15', None),
            ('MSS[0]', '16', None),
            ('MSS[1]', '17', None),
            ('MSS[2]', '18', None),
            ('MSS[3]', '19', None),
            ('MSS[4]', '20', None),
            ('MSS[5]', '21', None),
            ('MSS[6]', '22', None),
            ('MSS[7]', '23', None),
            ('MSS[8]', '24', None),
            ('MSS[9]', '25', None),
            ('MSS[10]', '26', None),
            ('MSS[11]', '27', None),
            ('MSS[12]', '28', None),
            ('MSS[13]', '29', None),
            ('MSS[14]', '30', None),
            ('MSS[15]', '31', None),
        ]),
        (0x00070188, 'OEM config', [
            ('E_DLOAD_DISABLE', '0', None),
            ('ENUM_TIMEOUT', '1', None),
            ('FORCE_DLOAD_DISABLE', '2', None),
            ('FAST_BOOT[0]', '5', None),
            ('FAST_BOOT[1]', '6', None),
            ('FAST_BOOT[2]', '7', None),
            ('FAST_BOOT[3]', '8', None),
            ('FAST_BOOT[4]', '9', None),
            ('SW_FUSE_PROG_DISABLE', '12', None),
            ('SPDM_SECURE_MODE', '13', None),
            ('WDOG_EN', '14', None),
            ('PBL_LOG_DISABLE', '15', None),
            ('IMAGE_ENCRYPTION_ENABLE', '19', None),
            ('DISABLE_ROT_TRANSFER', '20', None),
            ('SW_ROT_USE_SERIAL_NUM', '21', None),
            ('USB_SS_DISABLE', '22', None),
            ('APPS_HASH_INTEGRITY_CHECK_DISABLE', '23', None),
            ('MSS_HASH_INTEGRITY_CHECK_DISABLE', '24', None),
            ('DEBUG_POLICY_DISABLE', '28', None),
            ('ALL_DEBUG_DISABLE', '29', None),
            ('SSC_Q6_ETM_DISABLE', '37', None),
            ('RPM_DAPEN_DISABLE', '38', None),
            ('DAP_DEVICEEN_DISABLE', '39', None),
            ('APPS0_DBGEN_DISABLE', '40', None),
            ('DAP_DBGEN_DISABLE', '42', None),
            ('LPASS_DBGEN_DISABLE', '43', None),
            ('WCSS_DBGEN_DISABLE', '44', None),
            ('RPM_DBGEN_DISABLE', '45', None),
            ('SSC_DBGEN_DISABLE', '47', None),
            ('SSC_Q6_DBGEN_DISABLE', '48', None),
            ('VENUS_0_DBGEN_DISABLE', '49', None),
            ('A5x_ISDB_DBGEN_DISABLE', '50', None),
            ('GSS_A5_DBGEN_DISABLE', '51', None),
            ('MSS_DBGEN_DISABLE', '52', None),
            ('APPS0_NIDEN_DISABLE', '53', None),
            ('DAP_NIDEN_DISABLE', '55', None),
            ('LPASS_NIDEN_DISABLE', '56', None),
            ('WCSS_NIDEN_DISABLE', '57', None),
            ('RPM_NIDEN_DISABLE', '58', None),
            ('SSC_NIDEN_DISABLE', '60', None),
            ('GSS_A5_NIDEN_DISABLE', '61', None),
            ('MSS_NIDEN_DISABLE', '62', None),
            ('APPS0_SPNIDEN_DISABLE', '63', None),
        ]),
        (0x00070190, 'OEM config', [
            ('DAP_SPNIDEN_DISABLE', '1', None),
            ('SSC_SPNIDEN_DISABLE', '3', None),
            ('GSS_A5_SPNIDEN_DISABLE', '4', None),
            ('APPS0_SPIDEN_DISABLE', '5', None),
            ('DAP_SPIDEN_DISABLE', '7', None),
            ('SSC_SPIDEN_DISABLE', '9', None),
            ('GSS_A5_SPIDEN_DISABLE', '10', None),
            ('SPARE_REG31_SECURE', '16', None),
            ('SPARE_REG32_SECURE', '17', None),
            ('SPARE_REG33_SECURE', '18', None),
            ('SPARE_REG34_SECURE', '19', None),
            ('SPARE_REG35_SECURE', '20', None),
            ('SPARE_REG36_SECURE', '21', None),
            ('SPARE_REG37_SECURE', '22', None),
            ('SPARE_REG38_SECURE', '23', None),
            ('SPARE_REG39_SECURE', '24', None),
            ('SPARE_REG40_SECURE', '25', None),
            ('SPARE_REG41_SECURE', '26', None),
            ('SPARE_REG42_SECURE', '27', None),
            ('SPARE_REG43_SECURE', '28', None),
            ('SPARE_REG44_SECURE', '29', None),
            ('OEM_HW_ID[0]', '32', None),
            ('OEM_HW_ID[1]', '33', None),
            ('OEM_HW_ID[2]', '34', None),
            ('OEM_HW_ID[3]', '35', None),
            ('OEM_HW_ID[4]', '36', None),
            ('OEM_HW_ID[5]', '37', None),
            ('OEM_HW_ID[6]', '38', None),
            ('OEM_HW_ID[7]', '39', None),
            ('OEM_HW_ID[8]', '40', None),
            ('OEM_HW_ID[9]', '41', None),
            ('OEM_HW_ID[10]', '42', None),
            ('OEM_HW_ID[11]', '43', None),
            ('OEM_HW_ID[12]', '44', None),
            ('OEM_HW_ID[13]', '45', None),
            ('OEM_HW_ID[14]', '46', None),
            ('OEM_HW_ID[15]', '47', None),
            ('OEM_PRODUCT_ID[0]', '48', None),
            ('OEM_PRODUCT_ID[1]', '49', None),
            ('OEM_PRODUCT_ID[2]', '50', None),
            ('OEM_PRODUCT_ID[3]', '51', None),
            ('OEM_PRODUCT_ID[4]', '52', None),
            ('OEM_PRODUCT_ID[5]', '53', None),
            ('OEM_PRODUCT_ID[6]', '54', None),
            ('OEM_PRODUCT_ID[7]', '55', None),
            ('OEM_PRODUCT_ID[8]', '56', None),
            ('OEM_PRODUCT_ID[9]', '57', None),
            ('OEM_PRODUCT_ID[10]', '58', None),
            ('OEM_PRODUCT_ID[11]', '59', None),
            ('OEM_PRODUCT_ID[12]', '60', None),
            ('OEM_PRODUCT_ID[13]', '61', None),
            ('OEM_PRODUCT_ID[14]', '62', None),
            ('OEM_PRODUCT_ID[15]', '63', None),
        ]),
        (0x00070198, 'OEM config', [
            ('PERIPH_PID[0]', '0', None),
            ('PERIPH_PID[1]', '1', None),
            ('PERIPH_PID[2]', '2', None),
            ('PERIPH_PID[3]', '3', None),
            ('PERIPH_PID[4]', '4', None),
            ('PERIPH_PID[5]', '5', None),
            ('PERIPH_PID[6]', '6', None),
            ('PERIPH_PID[7]', '7', None),
            ('PERIPH_PID[8]', '8', None),
            ('PERIPH_PID[9]', '9', None),
            ('PERIPH_PID[10]', '10', None),
            ('PERIPH_PID[11]', '11', None),
            ('PERIPH_PID[12]', '12', None),
            ('PERIPH_PID[13]', '13', None),
            ('PERIPH_PID[14]', '14', None),
            ('PERIPH_PID[15]', '15', None),
            ('PERIPH_VID[0]', '16', None),
            ('PERIPH_VID[1]', '17', None),
            ('PERIPH_VID[2]', '18', None),
            ('PERIPH_VID[3]', '19', None),
            ('PERIPH_VID[4]', '20', None),
            ('PERIPH_VID[5]', '21', None),
            ('PERIPH_VID[6]', '22', None),
            ('PERIPH_VID[7]', '23', None),
            ('PERIPH_VID[8]', '24', None),
            ('PERIPH_VID[9]', '25', None),
            ('PERIPH_VID[10]', '26', None),
            ('PERIPH_VID[11]', '27', None),
            ('PERIPH_VID[12]', '28', None),
            ('PERIPH_VID[13]', '29', None),
            ('PERIPH_VID[14]', '30', None),
            ('PERIPH_VID[15]', '31', None),
            ('ANTI_ROLLBACK_FEATURE_EN[0]', '32', None),
            ('ANTI_ROLLBACK_FEATURE_EN[1]', '33', None),
            ('ANTI_ROLLBACK_FEATURE_EN[2]', '34', None),
            ('ANTI_ROLLBACK_FEATURE_EN[3]', '35', None),
            ('ANTI_ROLLBACK_FEATURE_EN[4]', '36', None),
            ('ANTI_ROLLBACK_FEATURE_EN[5]', '37', None),
            ('ANTI_ROLLBACK_FEATURE_EN[6]', '38', None),
            ('ANTI_ROLLBACK_FEATURE_EN[7]', '39', None),
        ]),
        (0x00070378, 'OEM secure boot', [
            ('OEM_SECURE_BOOT1_ROM_PK_HASH_IDX0', '0', None),
            ('OEM_SECURE_BOOT1_ROM_PK_HASH_IDX1', '1', None),
            ('OEM_SECURE_BOOT1_ROM_PK_HASH_IDX2', '2', None),
            ('OEM_SECURE_BOOT1_ROM_PK_HASH_IDX3', '3', None),
            ('OEM_SECURE_BOOT1_PK_HASH_IN_FUSE', '4', None),
            ('OEM_SECURE_BOOT1_AUTH_EN', '5', None),
            ('OEM_SECURE_BOOT1_USE_SERIAL_NUM', '6', None),
            ('OEM_SECURE_BOOT2_ROM_PK_HASH_IDX0', '8', None),
            ('OEM_SECURE_BOOT2_ROM_PK_HASH_IDX1', '9', None),
            ('OEM_SECURE_BOOT2_ROM_PK_HASH_IDX2', '10', None),
            ('OEM_SECURE_BOOT2_ROM_PK_HASH_IDX3', '11', None),
            ('OEM_SECURE_BOOT2_PK_HASH_IN_FUSE', '12', None),
            ('OEM_SECURE_BOOT2_AUTH_EN', '13', None),
            ('OEM_SECURE_BOOT2_USE_SERIAL_NUM', '14', None),
            ('OEM_SECURE_BOOT3_ROM_PK_HASH_IDX0', '16', None),
            ('OEM_SECURE_BOOT3_ROM_PK_HASH_IDX1', '17', None),
            ('OEM_SECURE_BOOT3_ROM_PK_HASH_IDX2', '18', None),
            ('OEM_SECURE_BOOT3_ROM_PK_HASH_IDX3', '19', None),
            ('OEM_SECURE_BOOT3_PK_HASH_IN_FUSE', '20', None),
            ('OEM_SECURE_BOOT3_AUTH_EN', '21', None),
            ('OEM_SECURE_BOOT3_USE_SERIAL_NUM', '22', None),
            ('OEM_SECURE_BOOT4_ROM_PK_HASH_IDX0', '24', None),
            ('OEM_SECURE_BOOT4_ROM_PK_HASH_IDX1', '25', None),
            ('OEM_SECURE_BOOT4_ROM_PK_HASH_IDX2', '26', None),
            ('OEM_SECURE_BOOT4_ROM_PK_HASH_IDX3', '27', None),
            ('OEM_SECURE_BOOT4_PK_HASH_IN_FUSE', '28', None),
            ('OEM_SECURE_BOOT4_AUTH_EN', '29', None),
            ('OEM_SECURE_BOOT4_USE_SERIAL_NUM', '30', None),
            ('OEM_SECURE_BOOT5_ROM_PK_HASH_IDX0', '32', None),
            ('OEM_SECURE_BOOT5_ROM_PK_HASH_IDX1', '33', None),
            ('OEM_SECURE_BOOT5_ROM_PK_HASH_IDX2', '34', None),
            ('OEM_SECURE_BOOT5_ROM_PK_HASH_IDX3', '35', None),
            ('OEM_SECURE_BOOT5_PK_HASH_IN_FUSE', '36', None),
            ('OEM_SECURE_BOOT5_AUTH_EN', '37', None),
            ('OEM_SECURE_BOOT5_USE_SERIAL_NUM', '38', None),
            ('OEM_SECURE_BOOT6_ROM_PK_HASH_IDX0', '40', None),
            ('OEM_SECURE_BOOT6_ROM_PK_HASH_IDX1', '41', None),
            ('OEM_SECURE_BOOT6_ROM_PK_HASH_IDX2', '42', None),
            ('OEM_SECURE_BOOT6_ROM_PK_HASH_IDX3', '43', None),
            ('OEM_SECURE_BOOT6_PK_HASH_IN_FUSE', '44', None),
            ('OEM_SECURE_BOOT6_AUTH_EN', '45', None),
            ('OEM_SECURE_BOOT6_USE_SERIAL_NUM', '46', None),
            ('OEM_SECURE_BOOT7_ROM_PK_HASH_IDX0', '48', None),
            ('OEM_SECURE_BOOT7_ROM_PK_HASH_IDX1', '49', None),
            ('OEM_SECURE_BOOT7_ROM_PK_HASH_IDX2', '50', None),
            ('OEM_SECURE_BOOT7_ROM_PK_HASH_IDX3', '51', None),
            ('OEM_SECURE_BOOT7_PK_HASH_IN_FUSE', '52', None),
            ('OEM_SECURE_BOOT7_AUTH_EN', '53', None),
            ('OEM_SECURE_BOOT7_USE_SERIAL_NUM', '54', None),
            ('FEC bit', '56', None),
            ('FEC bit', '57', None),
            ('FEC bit', '58', None),
            ('FEC bit', '59', None),
            ('FEC bit', '60', None),
            ('FEC bit', '61', None),
            ('FEC bit', '62', None),
            ('Reserved', '63', None),
        ]),
        (0x00070380, 'OEM secure boot', [
            ('OEM_SECURE_BOOT8_ROM_PK_HASH_IDX0', '0', None),
            ('OEM_SECURE_BOOT8_ROM_PK_HASH_IDX1', '1', None),
            ('OEM_SECURE_BOOT8_ROM_PK_HASH_IDX2', '2', None),
            ('OEM_SECURE_BOOT8_ROM_PK_HASH_IDX3', '3', None),
            ('OEM_SECURE_BOOT8_PK_HASH_IN_FUSE', '4', None),
            ('OEM_SECURE_BOOT8_AUTH_EN', '5', None),
            ('OEM_SECURE_BOOT8_USE_SERIAL_NUM', '6', None),
            ('OEM_SECURE_BOOT9_ROM_PK_HASH_IDX0', '8', None),
            ('OEM_SECURE_BOOT9_ROM_PK_HASH_IDX1', '9', None),
            ('OEM_SECURE_BOOT9_ROM_PK_HASH_IDX2', '10', None),
            ('OEM_SECURE_BOOT9_ROM_PK_HASH_IDX3', '11', None),
            ('OEM_SECURE_BOOT9_PK_HASH_IN_FUSE', '12', None),
            ('OEM_SECURE_BOOT9_AUTH_EN', '13', None),
            ('OEM_SECURE_BOOT9_USE_SERIAL_NUM', '14', None),
            ('OEM_SECURE_BOOT10_ROM_PK_HASH_IDX0', '16', None),
            ('OEM_SECURE_BOOT10_ROM_PK_HASH_IDX1', '17', None),
            ('OEM_SECURE_BOOT10_ROM_PK_HASH_IDX2', '18', None),
            ('OEM_SECURE_BOOT10_ROM_PK_HASH_IDX3', '19', None),
            ('OEM_SECURE_BOOT10_PK_HASH_IN_FUSE', '20', None),
            ('OEM_SECURE_BOOT10_AUTH_EN', '21', None),
            ('OEM_SECURE_BOOT10_USE_SERIAL_NUM', '22', None),
            ('OEM_SECURE_BOOT11_ROM_PK_HASH_IDX0', '24', None),
            ('OEM_SECURE_BOOT11_ROM_PK_HASH_IDX1', '25', None),
            ('OEM_SECURE_BOOT11_ROM_PK_HASH_IDX2', '26', None),
            ('OEM_SECURE_BOOT11_ROM_PK_HASH_IDX3', '27', None),
            ('OEM_SECURE_BOOT11_PK_HASH_IN_FUSE', '28', None),
            ('OEM_SECURE_BOOT11_AUTH_EN', '29', None),
            ('OEM_SECURE_BOOT11_USE_SERIAL_NUM', '30', None),
            ('OEM_SECURE_BOOT12_ROM_PK_HASH_IDX0', '32', None),
            ('OEM_SECURE_BOOT12_ROM_PK_HASH_IDX1', '33', None),
            ('OEM_SECURE_BOOT12_ROM_PK_HASH_IDX2', '34', None),
            ('OEM_SECURE_BOOT12_ROM_PK_HASH_IDX3', '35', None),
            ('OEM_SECURE_BOOT12_PK_HASH_IN_FUSE', '36', None),
            ('OEM_SECURE_BOOT12_AUTH_EN', '37', None),
            ('OEM_SECURE_BOOT12_USE_SERIAL_NUM', '38', None),
            ('OEM_SECURE_BOOT13_ROM_PK_HASH_IDX0', '40', None),
            ('OEM_SECURE_BOOT13_ROM_PK_HASH_IDX1', '41', None),
            ('OEM_SECURE_BOOT13_ROM_PK_HASH_IDX2', '42', None),
            ('OEM_SECURE_BOOT13_ROM_PK_HASH_IDX3', '43', None),
            ('OEM_SECURE_BOOT13_PK_HASH_IN_FUSE', '44', None),
            ('OEM_SECURE_BOOT13_AUTH_EN', '45', None),
            ('OEM_SECURE_BOOT13_USE_SERIAL_NUM', '46', None),
            ('OEM_SECURE_BOOT14_ROM_PK_HASH_IDX0', '48', None),
            ('OEM_SECURE_BOOT14_ROM_PK_HASH_IDX1', '49', None),
            ('OEM_SECURE_BOOT14_ROM_PK_HASH_IDX2', '50', None),
            ('OEM_SECURE_BOOT14_ROM_PK_HASH_IDX3', '51', None),
            ('OEM_SECURE_BOOT14_PK_HASH_IN_FUSE', '52', None),
            ('OEM_SECURE_BOOT14_AUTH_EN', '53', None),
            ('OEM_SECURE_BOOT14_USE_SERIAL_NUM', '54', None),
            ('FEC bit', '56', None),
            ('FEC bit', '57', None),
            ('FEC bit', '58', None),
            ('FEC bit', '59', None),
            ('FEC bit', '60', None),
            ('FEC bit', '61', None),
            ('FEC bit', '62', None),
            ('Reserved', '63', None),
        ]),
    ],
}



def is_sec_dat(data):
    if len(data) < 12:
        return False
    m1, m2 = struct.unpack_from('<II', data, 0)
    return m1 == SECDAT_MAGIC1 and m2 == SECDAT_MAGIC2

def _fuse_rows(entries, region_map, op_map):
    # fuse entry is <IIIII> region_type, address, lsb, msb, operation
    rows = [('Index', 'Region Type', 'MSB', 'LSB', 'Operation', 'Address')]
    for i, (rt, addr, lsb, msb, op) in enumerate(entries):
        rows.append((str(i), str(region_map.get(rt, rt)), hexs(msb), f"{lsb:x}",
                     str(op_map.get(op, op)), hexs(addr)))
    return rows

def _augment_fuse_rows(entries, fuse_rows):
    # decode each blown value (lsb | msb<<32) to the named fuses it sets, using the
    # fuse-blow table for this soc; only fuses with a nonzero value are listed
    addr_map = {addr: (region, fuses) for addr, region, fuses in fuse_rows}
    rows = [('Region', 'Address', 'Bits', 'Fuse Name', 'Value')]
    for rt, addr, lsb, msb, op in entries:
        hit = addr_map.get(addr)
        if not hit:
            continue
        region, fuses = hit
        val = lsb | (msb << 32)
        for name, bits, rec in fuses:
            if ':' in bits:
                hi, lo = (int(x) for x in bits.split(':'))
                v = (val >> lo) & ((1 << (hi - lo + 1)) - 1)
                if not v:
                    continue
                vs, bs = hexs(v), f"{hi}:{lo}"
            else:
                b = int(bits); v = (val >> b) & 1
                if not v:
                    continue
                vs, bs = '1', str(b)
            rows.append((region, hexs(addr), bs, name, vs))
    return rows if len(rows) > 1 else None

def _autodetect_fuse_rows(entries):
    # no soc match (standalone sec.dat): pick a built-in table iff exactly one has
    # addresses that overlap the entries (msm8996 0x70xxx vs tme 0x221cxxxx are distinct)
    addrs = {addr for _, addr, _, _, _ in entries}
    hits = [rows for rows in FUSE_TABLES.values() if any(a in addrs for a, _, _ in rows)]
    return (hits[0], 'built-in table') if len(hits) == 1 else (None, None)

def _print_fuse_augmented(entries, fuse_rows, src):
    if not entries:
        return
    if not fuse_rows:
        fuse_rows, src = _autodetect_fuse_rows(entries)
    if not fuse_rows:
        section("Decoded Fuses")
        print(c(YELLOW, "  Fuse-name decode not supported for this SoC."))
        print(f"  {DIM}Provide --security-profile <soc_security_profile.xml> to name the fuses.{RESET}")
        return
    rows = _augment_fuse_rows(entries, fuse_rows)
    if not rows:
        return
    section("Decoded Fuses (what this file blows)")
    print(f"  {DIM}(fuse names from {src}; only nonzero-value fuses listed){RESET}")
    print(_render_table(rows))

def _read_secdat_segment(data, seg_off, seg_type, fuse_rows=None, src=None):
    # segment = fuse header (version, size, count, reserved) + count fuse entries
    ver, fsize, fcount = struct.unpack_from('<III', data, seg_off)
    section(f"{seg_type} Segment Header")
    field("Version", ver)
    field("Total Fuse Entries Size", f"{fsize} (bytes)")
    field("Number of Fuse Entries", fcount)
    off = seg_off + 28
    entries = []
    for _ in range(fcount):
        entries.append(struct.unpack_from('<IIIII', data, off)); off += 20
    if entries:
        section(f"{seg_type} Segment Entries")
        print(_render_table(_fuse_rows(entries, SECDAT_REGION_V1, SECDAT_OP_V1)))
        _print_fuse_augmented(entries, fuse_rows, src)
    return off

def print_sec_dat(data, fuse_rows=None, src=None):
    m1, m2, ver = struct.unpack_from('<III', data, 0)
    section("Sec Dat Header")
    field("Magic 1", hexs(m1)); field("Magic 2", hexs(m2)); field("Version", ver)
    if ver == 3:
        fcount = struct.unpack_from('<I', data, 12)[0]
        field("Number of Fuse Entries", fcount)
        off = 16
        entries = []
        for _ in range(fcount):
            entries.append(struct.unpack_from('<IIIII', data, off)); off += 20
        section("Fuse Entries")
        print(_render_table(_fuse_rows(entries, SECDAT_REGION_V3, SECDAT_OP_V3)))
        _print_fuse_augmented(entries, fuse_rows, src)
        return
    if ver == 2:
        sz, info, num_seg = struct.unpack_from('<I16sI', data, 12)
        field("Sec Dat Data Size", f"{sz} (bytes)")
        field("Info", info.rstrip(b'\x00').decode('latin1'))
        field("Number of Segments", num_seg)
        seg_hdrs = []
        off = 48
        for _ in range(num_seg):
            so, st, attr = struct.unpack_from('<IHH', data, off); off += 8
            seg_hdrs.append((so, st, attr))
        section("Segment Headers")
        rows = [('Index', 'Offset', 'Type')]
        for i, (so, st, attr) in enumerate(seg_hdrs):
            rows.append((str(i), hexs(so), str(SECDAT_SEG_TYPE.get(st, st))))
        print(_render_table(rows))
        end = 48
        for so, st, attr in seg_hdrs:
            end = _read_secdat_segment(data, so, SECDAT_SEG_TYPE.get(st, st), fuse_rows, src)
        footer = struct.unpack_from('<32s', data, end)[0]
        section("Sec Dat Footer"); field("Footer", footer.hex())
        return
    if ver == 1:
        sz, info, _res = struct.unpack_from('<I16s16s', data, 12)
        field("Sec Dat Data Size", f"{sz} (bytes)")
        field("Info", info.rstrip(b'\x00').decode('latin1'))
        off = 48
        if sz != 32:
            off = _read_secdat_segment(data, off, 'Efuse', fuse_rows, src)
        footer = struct.unpack_from('<32s', data, off)[0]
        section("Sec Dat Footer"); field("Footer", footer.hex())
        return
    print(c(YELLOW, f"  sec dat version {ver} not structured here."))

def _hashseg_soc(seg):
    # first soc hw version from a v7 hash table segment's qti/oem metadata
    try:
        _res, ver, cms, qms, oms = struct.unpack_from('<IIIII', seg, 0)
    except struct.error:
        return None
    if ver != 7:
        return None
    fmt = '<' + 'IIII' + 'I' * NUM_SOC_HW_VERS + 'II' + 'Q' * NUM_SERIALS + 'IIIII' + '64s' + 'I'
    for moff, msz in ((40 + cms, qms), (40 + cms + qms, oms)):
        if msz >= 224 and len(seg) >= moff + 224:
            v = struct.unpack_from(fmt, seg, moff)
            soc = [x for x in v[4:4 + NUM_SOC_HW_VERS] if x]
            if soc:
                return hexs(soc[0]).lower()
    return None

def _fuse_rows_for(soc, profiles):
    # prefer a passed --security-profile, else the built-in table for this soc
    if soc and profiles and profiles.get(soc, {}).get('fuse_table'):
        return profiles[soc]['fuse_table'], 'security profile'
    if soc and soc in FUSE_TABLES:
        return FUSE_TABLES[soc], 'built-in table'
    # no soc match (e.g. standalone sec.dat): use a passed profile's table if any
    for d in (profiles or {}).values():
        if d.get('fuse_table'):
            return d['fuse_table'], 'security profile'
    return None, None

def print_summary(data, all_roots):
    header("SUMMARY")
    print(f"  {DIM}Made by Littlenine Ennea{RESET}")
    section("File")
    field("Total size", f"0x{len(data):x}  ({len(data):,} bytes)")
    field("Entropy", f"{_entropy(data):.4f} bits/byte")
    if data[-0x200:].count(b'\xff') > 0x100:
        field("Tail content", "Flash erase padding (0xFF)")

    section("OEM_PK_HASH (device / QFIL Loader PK hash = SHA of FULL root cert DER)")
    roots = []
    for r in all_roots:
        if r['root'] and r['root'] not in roots:
            roots.append(r['root'])
    if not roots:
        print(c(RED, "  No root certificates found"))
        return
    for i, root in enumerate(roots):
        print(f"\n  Root #{i+1}: {c(BOLD, root['info'].get('subject'))}")
        print(f"  {'cert-DER SHA256':<26} {c(GREEN, hashlib.sha256(root['der']).hexdigest())}  {DIM}<- secboot_sha2_root{RESET}")
        print(f"  {'cert-DER SHA384':<26} {c(GREEN, hashlib.sha384(root['der']).hexdigest())}  {DIM}<- default sha384 root{RESET}")
        pk256, pk384 = _pubkey_hashes(root['der'])
        if pk256:
            print(f"  {DIM}SPKI SHA256 (pubkey only, NOT the fuse): {pk256}{RESET}")
        if pk384:
            print(f"  {DIM}SPKI SHA384 (pubkey only, NOT the fuse): {pk384}{RESET}")

def main():
    ap = argparse.ArgumentParser(description='Qualcomm MBN/ELF firmware image inspector')
    ap.add_argument('file', help='input .elf / .mbn / .melf')
    ap.add_argument('-v', '--verbose', action='count', default=0, help='-v x509 chain, -vv hex dumps')
    ap.add_argument('--security-profile', nargs='+', help='profile xml(s) to name tme debug options and fuses')
    args = ap.parse_args()
    profiles = load_security_profiles(args.security_profile)

    if not os.path.isfile(args.file):
        print(c(RED, f"Error: file not found: {args.file}")); sys.exit(1)
    with open(args.file, 'rb') as f:
        data = f.read()

    header(f"Qualcomm Firmware Inspector  -  {os.path.basename(args.file)}")
    print(f"  {DIM}Author : Littlenine (github.com/LittlenineEnnea){RESET}")
    print(f"  File: {args.file}")
    print(f"  Size: {len(data):,} bytes  (0x{len(data):x})")
    print(f"  MD5:  {hashlib.md5(data).hexdigest()}")
    print(f"  SHA256: {hashlib.sha256(data).hexdigest()}")

    # standalone sec.dat fuse image (not an elf)
    if is_sec_dat(data):
        fr, fsrc = _fuse_rows_for(None, profiles)
        print_sec_dat(data, fr, fsrc)
        print_summary(data, [])
        print()
        return

    elf, segments = parse_elf(data, args.verbose)
    if elf is None:
        sys.exit(1)

    # a sec-elf fuse file names its fuses per soc; get the soc from the hash segment
    hp = elf['hash_phdr']
    img_soc = _hashseg_soc(data[hp['offset']:hp['offset'] + hp['filesz']]) if hp else None
    fuse_rows, fuse_src = _fuse_rows_for(img_soc, profiles)

    # extra segments (apdp/debug policy tme, multi-image, sec-elf fuse) sit in a
    # load segment before the hash segment
    for s in segments:
        if s['os_type'] in (OS_SEG_HASH, OS_SEG_PHDR) or not s['filesz']:
            continue
        sd = data[s['offset']:s['offset'] + s['filesz']]
        if is_tme_segment(sd):
            print_tme_segment(sd, profiles); break
        if is_multi_image_segment(sd):
            print_multi_image_segment(sd); break
        if is_sec_dat(sd):
            print_sec_dat(sd, fuse_rows, fuse_src); break

    all_roots = []
    hp = elf['hash_phdr']
    if not hp:
        section("Signing Info")
        print(c(YELLOW, "  No Hash Table Segment (unsigned image, or a non-MBN / TME container)."))
    else:
        seg = data[hp['offset']:hp['offset'] + hp['filesz']]
        ver = struct.unpack_from('<I', seg, 4)[0]
        parsers = {3: parse_v3, 5: parse_v5, 6: parse_v6, 7: parse_v7, 8: parse_v8}
        try:
            if ver in parsers:
                all_roots = parsers[ver](seg)
            else:
                section("Hash Table Segment Header")
                field("Version", ver)
                print(c(YELLOW, f"  hash table segment version {ver} not structured here."))
        except Exception as e:
            print(c(RED, f"  hash table segment parse error: {e}"))

    if all_roots:
        print_cert_chains(all_roots, args.verbose)
    print_summary(data, all_roots)
    print()

if __name__ == '__main__':
    main()
