
#include <stddef.h>

#include "ota_os_interface.h"
#include "ota_private.h"


/**
 * @brief Validate JSON document and the DocModel.
 *
 * @param[in] pJson JSON job document.
 * @param[in] messageLength  Length of the job document.
 * @return DocParseErr_t DocParseErrNone if successful, JSON document parser errors.
 */

DocParseErr_t validateJSON( const char * pJson,
                                   uint32_t messageLength );

/**
 * @brief Store the parameter from the json to the offset specified by the document model.
 *
 * @param[in] docParam Structure to store the details of keys and where to store them.
 * @param[in] pContextBase Start of file context.
 * @param[in] pValueInJson Pointer to the value of the key in JSON buffer.
 * @param[in] valueLength Length of the value.
 * @return DocParseErr_t DocParseErrNone if successful, JSON document parser errors.
 */
DocParseErr_t extractParameter( JsonDocParam_t docParam,
                                       OtaMallocInterface_t * pMallocInterface,
                                       void * pContextBase,
                                       const char * pValueInJson,
                                       size_t valueLength );

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
                                       OtaMallocInterface_t * pMallocInterface );

 DocParseErr_t initDocModel( JsonDocModel_t * pDocModel,
                                   const JsonDocParam_t * pBodyDef,
                                   void * contextBaseAddr,
                                   uint32_t contextSize,
                                   uint16_t numJobParams );
