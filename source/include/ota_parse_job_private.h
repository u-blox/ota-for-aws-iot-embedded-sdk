
#include <stddef.h>

#include "ota_os_interface.h"
#include "ota_private.h"

DocParseErr_t parseOtaDocument( const char * pJson,
                                uint32_t messageLength,
                                const OtaMallocInterface_t * pMallocInterface,
                                OtaFileContext_t * pFileContext );
