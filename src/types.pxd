"""
Definitions imported from PKCS11 C headers.
"""

cdef extern from '../extern/pkcs11.h':

    ctypedef unsigned char CK_BYTE
    ctypedef CK_BYTE CK_BBOOL
    ctypedef CK_BYTE CK_UTF8CHAR
    ctypedef unsigned char CK_CHAR
    ctypedef unsigned long int CK_ULONG
    ctypedef CK_ULONG CK_ATTRIBUTE_TYPE
    ctypedef CK_ULONG CK_EC_KDF_TYPE
    ctypedef CK_ULONG CK_MECHANISM_TYPE
    ctypedef CK_ULONG CK_NOTIFICATION
    ctypedef CK_ULONG CK_OBJECT_HANDLE
    ctypedef CK_ULONG CK_RSA_PKCS_MGF_TYPE
    ctypedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE
    ctypedef CK_ULONG CK_SESSION_HANDLE
    ctypedef CK_ULONG CK_SLOT_ID

    ctypedef CK_ULONG CK_RV
    ctypedef enum:
        CKR_OK,
        CKR_CANCEL,
        CKR_HOST_MEMORY,
        CKR_SLOT_ID_INVALID,

        CKR_GENERAL_ERROR,
        CKR_FUNCTION_FAILED,

        CKR_ARGUMENTS_BAD,
        CKR_NO_EVENT,
        CKR_NEED_TO_CREATE_THREADS,
        CKR_CANT_LOCK,

        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_DATA_INVALID,
        CKR_DATA_LEN_RANGE,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_MEMORY,
        CKR_DEVICE_REMOVED,
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_ENCRYPTED_DATA_LEN_RANGE,
        CKR_FUNCTION_CANCELED,
        CKR_FUNCTION_NOT_PARALLEL,

        CKR_FUNCTION_NOT_SUPPORTED,

        CKR_KEY_HANDLE_INVALID,

        CKR_KEY_SIZE_RANGE,
        CKR_KEY_TYPE_INCONSISTENT,

        CKR_KEY_NOT_NEEDED,
        CKR_KEY_CHANGED,
        CKR_KEY_NEEDED,
        CKR_KEY_INDIGESTIBLE,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_UNEXTRACTABLE,

        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,

        CKR_OBJECT_HANDLE_INVALID,
        CKR_OPERATION_ACTIVE,
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_PIN_INCORRECT,
        CKR_PIN_INVALID,
        CKR_PIN_LEN_RANGE,

        CKR_PIN_EXPIRED,
        CKR_PIN_LOCKED,

        CKR_SESSION_CLOSED,
        CKR_SESSION_COUNT,
        CKR_SESSION_HANDLE_INVALID,
        CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        CKR_SESSION_READ_ONLY,
        CKR_SESSION_EXISTS,

        CKR_SESSION_READ_ONLY_EXISTS,
        CKR_SESSION_READ_WRITE_SO_EXISTS,

        CKR_SIGNATURE_INVALID,
        CKR_SIGNATURE_LEN_RANGE,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_TOKEN_NOT_PRESENT,
        CKR_TOKEN_NOT_RECOGNIZED,
        CKR_TOKEN_WRITE_PROTECTED,
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        CKR_UNWRAPPING_KEY_SIZE_RANGE,
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_USER_ALREADY_LOGGED_IN,
        CKR_USER_NOT_LOGGED_IN,
        CKR_USER_PIN_NOT_INITIALIZED,
        CKR_USER_TYPE_INVALID,

        CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        CKR_USER_TOO_MANY_TYPES,

        CKR_WRAPPED_KEY_INVALID,
        CKR_WRAPPED_KEY_LEN_RANGE,
        CKR_WRAPPING_KEY_HANDLE_INVALID,
        CKR_WRAPPING_KEY_SIZE_RANGE,
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_RANDOM_SEED_NOT_SUPPORTED,

        CKR_RANDOM_NO_RNG,

        CKR_DOMAIN_PARAMS_INVALID,

        CKR_BUFFER_TOO_SMALL,
        CKR_SAVED_STATE_INVALID,
        CKR_INFORMATION_SENSITIVE,
        CKR_STATE_UNSAVEABLE,

        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_CRYPTOKI_ALREADY_INITIALIZED,
        CKR_MUTEX_BAD,
        CKR_MUTEX_NOT_LOCKED,

        CKR_NEW_PIN_MODE,
        CKR_NEXT_OTP,
        CKR_EXCEEDED_MAX_ITERATIONS,
        CKR_FIPS_SELF_TEST_FAILED,
        CKR_LIBRARY_LOAD_FAILED,
        CKR_PIN_TOO_WEAK,
        CKR_PUBLIC_KEY_INVALID,

        CKR_FUNCTION_REJECTED,

        CKR_VENDOR_DEFINED,

    ctypedef CK_ULONG CK_USER_TYPE
    ctypedef enum:
        CKU_SO,
        CKU_USER,
        CKU_CONTEXT_SPECIFIC,

    cdef enum:
        CK_TRUE,
        CK_FALSE,

    ctypedef CK_ULONG CK_FLAGS
    cdef enum:
        CKF_RW_SESSION,
        CKF_SERIAL_SESSION,

    cdef enum:  # CKZ
        CKZ_DATA_SPECIFIED,

    ctypedef struct CK_VERSION:
        CK_BYTE major
        CK_BYTE minor

    ctypedef struct CK_INFO:
        CK_VERSION cryptokiVersion;
        CK_UTF8CHAR manufacturerID[32]
        CK_FLAGS flags

        CK_UTF8CHAR libraryDescription[32]
        CK_VERSION libraryVersion;

    ctypedef struct CK_SLOT_INFO:
        CK_UTF8CHAR slotDescription[64]
        CK_UTF8CHAR manufacturerID[32]
        CK_FLAGS flags

        CK_VERSION hardwareVersion
        CK_VERSION firmwareVersion

    ctypedef struct CK_MECHANISM_INFO:
        CK_ULONG ulMinKeySize
        CK_ULONG ulMaxKeySize
        CK_FLAGS flags

    ctypedef struct CK_TOKEN_INFO:
        CK_UTF8CHAR label[32]
        CK_UTF8CHAR manufacturerID[32]
        CK_UTF8CHAR model[16]
        CK_CHAR serialNumber[16]
        CK_FLAGS flags

        CK_ULONG ulMaxSessionCount
        CK_ULONG ulSessionCount
        CK_ULONG ulMaxRwSessionCount
        CK_ULONG ulRwSessionCount
        CK_ULONG ulMaxPinLen
        CK_ULONG ulMinPinLen
        CK_ULONG ulTotalPublicMemory
        CK_ULONG ulFreePublicMemory
        CK_ULONG ulTotalPrivateMemory
        CK_ULONG ulFreePrivateMemory
        CK_VERSION hardwareVersion
        CK_VERSION firmwareVersion
        CK_CHAR utcTime[16]

    ctypedef struct CK_MECHANISM:
        CK_MECHANISM_TYPE mechanism
        void *pParameter
        CK_ULONG ulParameterLen

    ctypedef struct CK_ATTRIBUTE:
        CK_ATTRIBUTE_TYPE type
        void *pValue
        CK_ULONG ulValueLen

    ctypedef struct CK_RSA_PKCS_OAEP_PARAMS:
        CK_MECHANISM_TYPE hashAlg
        CK_RSA_PKCS_MGF_TYPE mgf
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source
        void *pSourceData
        CK_ULONG ulSourceDataLen

    ctypedef struct CK_RSA_PKCS_PSS_PARAMS:
        CK_MECHANISM_TYPE hashAlg
        CK_RSA_PKCS_MGF_TYPE mgf
        CK_ULONG sLen

    ctypedef struct CK_ECDH1_DERIVE_PARAMS:
        CK_EC_KDF_TYPE kdf
        CK_ULONG ulSharedDataLen
        CK_BYTE *pSharedData
        CK_ULONG ulPublicDataLen
        CK_BYTE *pPublicData
