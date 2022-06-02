#ifndef OTA_PARSE_JOB_PRIVATE_H
#define OTA_PARSE_JOB_PRIVATE_H

#include <stddef.h>

#include "ota_os_interface.h"
#include "ota_private.h"

DocParseErr_t parseOtaDocument( const char * pJson,
                                uint32_t messageLength,
                                const OtaMallocInterface_t * pMallocInterface,
                                OtaFileContext_t * pFileContext );

#endif /* OTA_PARSE_JOB_PRIVATE_H */
