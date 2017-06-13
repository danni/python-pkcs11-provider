#include <Python.h>

#include "../extern/pkcs11.h"
#include "pkcs11.h"


static CK_BBOOL did_PyInitialize = CK_FALSE;


CK_RV
C_Initialize(void *flags)
{
    if (!Py_IsInitialized())
      {
        Py_Initialize();
        did_PyInitialize = CK_TRUE;
      }

    PyInit_pkcs11();
    return _C_Initialize(flags);
}


CK_RV
C_Finalize(void *flags)
{
    CK_RV rv = _C_Finalize(flags);

    if (did_PyInitialize)
      {
        Py_Finalize();
      }

    return rv;
}
