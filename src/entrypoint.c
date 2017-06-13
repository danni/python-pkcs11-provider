/**
 * PKCS#11 initialization routines.
 *
 * These are written in C so that we can initialize Python.
 */

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
    /* Call into our Cython initialize function. */
    return _C_Initialize(flags);
}


CK_RV
C_Finalize(void *flags)
{
    /* Call into our Cython finalize function. */
    CK_RV rv = _C_Finalize(flags);

    if (did_PyInitialize)
      {
        Py_Finalize();
      }

    return rv;
}
