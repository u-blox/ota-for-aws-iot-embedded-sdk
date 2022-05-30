
#include <stddef.h>

#include "core_json.h"
#include "ota_os_interface.h"
#include "ota_private.h"

typedef struct OtaFieldKey {
    const char * pName;
    size_t size;
} OtaFieldKey_t;

#define OTA_FIELD_KEY_CONST(x) { (x), sizeof((x)) }

typedef struct OtaFieldValue {
    const char* pData;
    size_t size;
    JSONTypes_t type;
} OtaFieldValue_t;

/**
 * @ingroup ota_private_struct_types
 * @brief JSON document parameter to store the details of keys and where to store them.
 *
 * This is a document parameter structure used by the document model. It determines
 * the type of parameter specified by the key name and where to store the parameter
 * locally when it is extracted from the JSON document. It also contains the
 * expected Jasmine type of the value field for validation.
 *
 * @note The destOffset field is an offset into the models context structure.
 */
typedef struct OtaFieldDescriptor
{
    OtaFieldKey_t key;                  /*!< Expected key name. */
    JSONTypes_t type;
} OtaFieldDescriptor_t;


/**
 * @brief Extract the desired fields from the JSON document based on the specified document model.
 *
 * @param[in] pJson JSON job document.
 * @param[in] messageLength  Length of the job document.
 * @param[in] pDocModel Details of expected parameters in the job doc.
 * @return DocParseErr_t DocParseErr_t DocParseErrNone if successful, JSON document parser errors.
 */
DocParseErr_t parseJSONbyModel( const char * pJson,
                                       uint32_t messageLength,
                                       JsonDocModel_t * pDocModel,
                                       const OtaMallocInterface_t * pMallocInterface );

 DocParseErr_t initDocModel( JsonDocModel_t * pDocModel,
                                   const JsonDocParam_t * pBodyDef,
                                   void * contextBaseAddr,
                                   uint32_t contextSize,
                                   uint16_t numJobParams );

/*
 * Layers of parser:
 *   1. batch object property parse
 *   2. validation of types and required properties
 *   3. decode/copy of extracted fields
 */

JSONStatus_t otajson_searchObjectFields( const char * pJson,
                                       uint32_t messageLength,
                                       uint32_t fieldCount,
                                       const OtaFieldDescriptor_t * pFieldDescriptors,
                                       OtaFieldValue_t * pFieldValues );