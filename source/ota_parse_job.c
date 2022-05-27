#include <assert.h>
#include <errno.h>
#include <string.h>

#include "core_json.h"
#include "ota_base64_private.h"
#include "ota_parse_job_private.h"

/**
 * @brief Decode the base64 encoded file signature key from the job document and store it in file context.
 *
 * @param[in] pValueInJson Pointer to the value of the key in JSON buffer.
 * @param[in] valueLength Length of the value.
 * @param[out] pParamAdd Pointer to the location where the value is stored.
 * @return DocParseErr_t DocParseErrNone if successful, JSON document parser errors.
 */
static DocParseErr_t decodeAndStoreKey( const char * pValueInJson,
                                        size_t valueLength,
                                        void * pParamAdd );

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
                                       const OtaMallocInterface_t * pMallocInterface,
                                       void * pContextBase,
                                       const char * pValueInJson,
                                       size_t valueLength );
/**
 * @brief Extract the value from json and store it into the allocated memory.
 *
 * @param[in] pKey Name of the Key to extract.
 * @param[in] pValueInJson Pointer to the value of the key in JSON buffer.
 * @param[in] valueLength Length of the value.
 * @param[out] pParamAdd Pointer to the location where the value is stored.
 * @param[in] pParamSizeAdd Size required to store the param.
 * @return DocParseErr_t DocParseErrNone if successful, JSON document parser errors.
 */
static DocParseErr_t extractAndStoreArray(
                                        const OtaMallocInterface_t * pMallocInterface,
                                         const char * pKey,
                                           const char * pValueInJson,
                                           size_t valueLength,
                                           void * pParamAdd,
                                           uint32_t * pParamSizeAdd );



/**
 * @brief Check if all the required parameters for job document are extracted from the JSON.
 *
 * @param[in] pModelParam Structure to store the details of keys and where to store them.
 * @param[in] pDocModel Details of expected parameters in the job doc.
 * @return DocParseErr_t DocParseErrNone if successful, JSON document parser errors.
 */
static DocParseErr_t verifyRequiredParamsExtracted( const JsonDocParam_t * pModelParam,
                                                    const JsonDocModel_t * pDocModel );

/* Validate JSON document and the DocModel*/
 DocParseErr_t validateJSON( const char * pJson,
                                   uint32_t messageLength )
{
    DocParseErr_t err = DocParseErrNone;
    JSONStatus_t result;

    /* Check JSON document pointer is valid.*/
    if( pJson == NULL )
    {
        LogError( ( "Parameter check failed: pJson is NULL." ) );
        err = DocParseErrNullDocPointer;
    }

    /* Check if the JSON document is valid*/
    if( err == DocParseErrNone )
    {
        result = JSON_Validate( pJson, ( size_t ) messageLength );

        if( result != JSONSuccess )
        {
            LogError( ( "Invalid JSON document: "
                        "JSON_Validate returned error: "
                        "JSONStatus_t=%d",
                        result ) );
            err = DocParseErr_InvalidJSONBuffer;
        }
    }

    return err;
}

/* Check if all the required parameters for job document are extracted from the JSON */

static DocParseErr_t verifyRequiredParamsExtracted( const JsonDocParam_t * pModelParam,
                                                    const JsonDocModel_t * pDocModel )
{
    uint32_t scanIndex = 0;
    DocParseErr_t err = DocParseErrNone;
    uint32_t missingParams = ( pDocModel->paramsReceivedBitmap & pDocModel->paramsRequiredBitmap )
                             ^ pDocModel->paramsRequiredBitmap;

    ( void ) pModelParam; /* For suppressing compiler-warning: unused variable. */

    if( missingParams != 0U )
    {
        /* The job document did not have all required document model parameters. */
        for( scanIndex = 0U; scanIndex < pDocModel->numModelParams; scanIndex++ )
        {
            if( ( missingParams & ( ( uint32_t ) 1U << scanIndex ) ) != 0U )
            {
                LogDebug( ( "Failed job document content check: "
                            "Required job document parameter was not extracted: "
                            "parameter=%s",
                            pModelParam[ scanIndex ].pSrcKey ) );
            }
        }

        err = DocParseErrMalformedDoc;
    }

    return err;
}


/* Extract the desired fields from the JSON document based on the specified document model. */

 DocParseErr_t parseJSONbyModel( const char * pJson,
                                       uint32_t messageLength,
                                       JsonDocModel_t * pDocModel,
                                       const OtaMallocInterface_t * pMallocInterface )
{
    const JsonDocParam_t * pModelParam = NULL;
    DocParseErr_t err;
    JSONStatus_t result;
    uint16_t paramIndex = 0;

    LogDebug( ( "JSON received: %s", pJson ) );

    /* Fetch the model parameters from the DocModel*/
    pModelParam = pDocModel->pBodyDef;

    /* Check the validity of the JSON document */
    err = validateJSON( pJson, messageLength );

    /* Traverse the docModel and search the JSON if it containing the Source Key specified*/
    for( paramIndex = 0; paramIndex < pDocModel->numModelParams; paramIndex++ )
    {
        const char * pQueryKey = pDocModel->pBodyDef[ paramIndex ].pSrcKey;
        size_t queryKeyLength = strlen( pQueryKey );
        const char * pValueInJson = NULL;
        size_t valueLength = 0;
        result = JSON_SearchConst( pJson, messageLength, pQueryKey, queryKeyLength, &pValueInJson, &valueLength, NULL );

        if( result == JSONSuccess )
        {
            /* Mark parameter as received in the bitmap. */
            pDocModel->paramsReceivedBitmap |= ( ( uint32_t ) 1U << paramIndex );

            if( OTA_DONT_STORE_PARAM == ( int32_t ) pModelParam[ paramIndex ].pDestOffset )
            {
                /* Do nothing if we don't need to store the parameter */
                continue;
            }
            else
            {
                err = extractParameter( pModelParam[ paramIndex ],
                                        pMallocInterface,
                                        pDocModel->contextBase,
                                        pValueInJson,
                                        valueLength );
            }

            if( err != DocParseErrNone )
            {
                break;
            }
        }
    }

    if( err == DocParseErrNone )
    {
        err = verifyRequiredParamsExtracted( pModelParam, pDocModel );
    }

    if( err != DocParseErrNone )
    {
        LogDebug( ( "Failed to parse JSON document as AFR_OTA job: "
                    "DocParseErr_t=%d",
                    err ) );
    }

    return err;
}

/* Prepare the document model for use by sanity checking the initialization parameters
 * and detecting all required parameters. */

 DocParseErr_t initDocModel( JsonDocModel_t * pDocModel,
                                   const JsonDocParam_t * pBodyDef,
                                   void * contextBaseAddr,
                                   uint32_t contextSize,
                                   uint16_t numJobParams )
{
    DocParseErr_t err = DocParseErrUnknown;
    uint32_t scanIndex;

    /* Sanity check the model pointers and parameter count. Exclude the context base address and size since
     * it is technically possible to create a model that writes entirely into absolute memory locations.
     */
    if( pDocModel == NULL )
    {
        LogError( ( "Parameter check failed: pDocModel is NULL." ) );
        err = DocParseErrNullModelPointer;
    }
    else if( pBodyDef == NULL )
    {
        LogError( ( "Parameter check failed: pBodyDef is NULL." ) );
        err = DocParseErrNullBodyPointer;
    }
    else if( numJobParams > OTA_DOC_MODEL_MAX_PARAMS )
    {
        LogError( ( "Parameter check failed: "
                    "Document model has %u parameters: "
                    "Document model should have <= %u parameters.",
                    numJobParams,
                    OTA_DOC_MODEL_MAX_PARAMS ) );
        err = DocParseErrTooManyParams;
    }
    else
    {
        pDocModel->contextBase = contextBaseAddr;
        pDocModel->contextSize = contextSize;
        pDocModel->pBodyDef = pBodyDef;
        pDocModel->numModelParams = numJobParams;
        pDocModel->paramsReceivedBitmap = 0;
        pDocModel->paramsRequiredBitmap = 0;

        /* Scan the model and detect all required parameters (i.e. not optional). */
        for( scanIndex = 0; scanIndex < pDocModel->numModelParams; scanIndex++ )
        {
            if( pDocModel->pBodyDef[ scanIndex ].required == true )
            {
                /* Add parameter to the required bitmap. */
                pDocModel->paramsRequiredBitmap |= ( ( uint32_t ) 1U << scanIndex );
            }
        }

        err = DocParseErrNone;
    }

    if( err != DocParseErrNone )
    {
        LogError( ( "Failed to initialize document model: "
                    "DocParseErr_t=%d", err ) );
    }

    return err;
}

/* Decode the base64 encoded file signature key from the job document and store it in file context*/

static DocParseErr_t decodeAndStoreKey( const char * pValueInJson,
                                        size_t valueLength,
                                        void * pParamAdd )
{
    DocParseErr_t err = DocParseErrNone;
    size_t actualLen = 0;
    Base64Status_t base64Status = Base64Success;
    Sig256_t ** pSig256 = pParamAdd;

    /* pSig256 should point to pSignature in OtaFileContext_t, which is statically allocated. */
    assert( *pSig256 != NULL );

    base64Status = base64Decode( ( *pSig256 )->data,
                                 sizeof( ( *pSig256 )->data ),
                                 &actualLen,
                                 ( const uint8_t * ) pValueInJson,
                                 valueLength );

    if( base64Status != Base64Success )
    {
        /* Stop processing on error. */
        LogError( ( "Failed to decode Base64 data: "
                    "base64Decode returned error: "
                    "error=%d",
                    base64Status ) );
        err = DocParseErrBase64Decode;
    }
    else
    {
        char pLogBuffer[ 33 ];
        ( void ) strncpy( pLogBuffer, pValueInJson, 32 );
        pLogBuffer[ 32 ] = '\0';
        LogInfo( ( "Extracted parameter [ %s: %s... ]",
                   OTA_JsonFileSignatureKey,
                   pLogBuffer ) );


        ( *pSig256 )->size = ( uint16_t ) actualLen;
    }

    return err;
}

/* Extract the value from json and store it into the allocated memory. */

 static DocParseErr_t extractAndStoreArray(
                                        const OtaMallocInterface_t * pMallocInterface,
                                         const char * pKey,
                                           const char * pValueInJson,
                                           size_t valueLength,
                                           void * pParamAdd,
                                           uint32_t * pParamSizeAdd )
{
    DocParseErr_t err = DocParseErrNone;

    /* For string and array, pParamAdd should be pointing to a uint8_t pointer. */
    char ** pCharPtr = pParamAdd;

    ( void ) pKey; /* For suppressing compiler-warning: unused variable. */

    if( *pParamSizeAdd == 0U )
    {
        /* Free previously allocated buffer. */
        if( *pCharPtr != NULL )
        {
            pMallocInterface->free( *pCharPtr );
        }

        /* Malloc memory for a copy of the value string plus a zero terminator. */
        *pCharPtr = pMallocInterface->malloc( valueLength + 1U );

        if( *pCharPtr == NULL )
        {
            /* Stop processing on error. */
            err = DocParseErrOutOfMemory;

            LogError( ( "Memory allocation failed "
                        "[key: valueLength]=[%s: %lu]",
                        pKey,
                        ( unsigned long ) valueLength ) );
        }
    }
    else
    {
        if( *pParamSizeAdd < ( valueLength + 1U ) )
        {
            err = DocParseErrUserBufferInsuffcient;

            LogError( ( "Insufficient user memory: "
                        "[key: valueLength]=[%s: %lu]",
                        pKey,
                        ( unsigned long ) valueLength ) );
        }
    }

    if( err == DocParseErrNone )
    {
        /* Copy parameter string into newly allocated memory. */
        ( void ) memcpy( *pCharPtr, pValueInJson, valueLength );

        /* Zero terminate the new string. */
        ( *pCharPtr )[ valueLength ] = '\0';

        LogInfo( ( "Extracted parameter: "
                   "[key: value]=[%s: %s]",
                   pKey,
                   *pCharPtr ) );
    }

    return err;
}

/* Store the parameter from the json to the offset specified by the document model. */

 DocParseErr_t extractParameter( JsonDocParam_t docParam,
                                   const OtaMallocInterface_t * pMallocInterface,
                                       void * pContextBase,
                                       const char * pValueInJson,
                                       size_t valueLength )
{
    DocParseErr_t err = DocParseErrNone;
    void * pParamAdd;
    uint32_t * pParamSizeAdd;

    /* Get destination offset to parameter storage location.*/
    pParamAdd = ( uint8_t * ) pContextBase + docParam.pDestOffset;

    if( ( ModelParamTypeStringCopy == docParam.modelParamType ) || ( ModelParamTypeArrayCopy == docParam.modelParamType ) )
    {
        /* Get destination buffer size to parameter storage location. */
        pParamSizeAdd = ( void * ) ( ( uint8_t * ) pContextBase + docParam.pDestSizeOffset );

        err = extractAndStoreArray( pMallocInterface, docParam.pSrcKey, pValueInJson, valueLength, pParamAdd, pParamSizeAdd );
    }
    else if( ModelParamTypeUInt32 == docParam.modelParamType )
    {
        uint32_t * pUint32 = pParamAdd;
        char * pEnd;
        const char * pStart = pValueInJson;
        errno = 0;

        *pUint32 = ( uint32_t ) strtoul( pStart, &pEnd, 0 );

        if( ( errno == 0 ) && ( pEnd == &pValueInJson[ valueLength ] ) )
        {
            LogInfo( ( "Extracted parameter: [key: value]=[%s: %u]",
                       docParam.pSrcKey, *pUint32 ) );
        }
        else
        {
            err = DocParseErrInvalidNumChar;
        }
    }
    else if( ModelParamTypeSigBase64 == docParam.modelParamType )
    {
        err = decodeAndStoreKey( pValueInJson, valueLength, pParamAdd );
    }
    else if( ModelParamTypeIdent == docParam.modelParamType )
    {
        LogDebug( ( "Identified parameter: [ %s ]",
                    docParam.pSrcKey ) );

        *( bool * ) pParamAdd = true;
    }
    else
    {
        LogWarn( ( "Invalid parameter type: %d", docParam.modelParamType ) );
    }

    if( err != DocParseErrNone )
    {
        LogDebug( ( "Failed to extract document parameter: error=%d, paramter key=%s",
                    err, docParam.pSrcKey ) );
    }

    return err;
}

