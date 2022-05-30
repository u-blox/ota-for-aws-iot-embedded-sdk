#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "ota.h"
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

JSONStatus_t otajson_searchObjectFields( const char * pJson,
                                       uint32_t messageLength,
                                       uint32_t fieldCount,
                                       const OtaFieldDescriptor_t * pFieldDescriptors,
                                       OtaFieldValue_t * pFieldValues )
{
    size_t start = 0;
    size_t next = 0;
    JSONStatus_t status = JSONSuccess;
    JSONPair_t pair;
    uint32_t fieldIndex;

    assert( pJson != NULL );

    for (fieldIndex = 0; fieldIndex < fieldCount; fieldIndex++) {
        pFieldValues[fieldIndex].pData = NULL;
        pFieldValues[fieldIndex].size = 0;
        pFieldValues[fieldIndex].type = JSONInvalid;
    }

    while (status == JSONSuccess) {
        status = JSON_Iterate(pJson, messageLength, &start, &next, &pair);
        if ( status != JSONSuccess ) {
            break;
        } else if (pair.key == NULL) {
            /* Expected to enumerate an object, but got an array. */
            status = JSONIllegalDocument;
            break;
        } else {
            /* Search the field descriptors for a match. */
            for (fieldIndex = 0; fieldIndex < fieldCount; fieldIndex++) {
                if ((pFieldDescriptors[fieldIndex].key.size == pair.keyLength) &&
                        (strncmp(pFieldDescriptors[fieldIndex].key.pName, pair.key, pair.keyLength) == 0)) {
                    if (pFieldDescriptors[fieldIndex].type != pair.jsonType) {
                        status = JSONIllegalDocument;
                    } else {
                        pFieldValues[fieldIndex].pData = pair.value;
                        pFieldValues[fieldIndex].size = pair.valueLength;
                        pFieldValues[fieldIndex].type = pair.jsonType;
                    }
                    break;
                }
            }
        }
    }

    if ( status == JSONNotFound ) {
        /* Reached the end of the object with no errors. */
        status = JSONSuccess;
    }
    return status;
}

DocParseErr_t otajson_SearchObject(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                const char ** ppOut,
                                size_t * pOutLength)
{
    DocParseErr_t err = DocParseErrNone;
    JSONStatus_t status;
    const char * value;
    size_t valueLength;
    JSONTypes_t valueType;

    status = JSON_SearchConst(pJson,
        jsonLength,
        key,
        keyLength,
        &value,
        &valueLength,
        &valueType);
    if (status == JSONSuccess) {
        if (valueType == JSONObject)
        {
            *ppOut = value;
            *pOutLength = valueLength;
        }
        else
        {
            err = DocParseErrFieldTypeMismatch;
        }
    }
    else if (!required && (status == JSONNotFound))
    {
        err = DocParseErrNotFound;
    }
    else
    {
        err = DocParseErrMalformedDoc;
    }

    return err;
}

DocParseErr_t otajson_SearchStringTerminate(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                char * out,
                                size_t outLength)
{
    DocParseErr_t err = DocParseErrNone;
    JSONStatus_t status;
    const char * value;
    size_t valueLength;
    JSONTypes_t valueType;

    status = JSON_SearchConst(pJson,
        jsonLength,
        key,
        keyLength,
        &value,
        &valueLength,
        &valueType);
    if (status == JSONSuccess) {
        if (valueType == JSONString)
        {
            if (out != NULL)
            {
                /* The output is expecting a NUL terminated string, so the raw value must be one byte smaller. */
                if (valueLength < outLength)
                {
                    memcpy(out, value, valueLength);
                    out[valueLength] = '\0';
                }
                else
                {
                    err = DocParseErrUserBufferInsuffcient;
                }
            }
        }
        else
        {
            err = DocParseErrFieldTypeMismatch;
        }
    }
    else if (!required && (status == JSONNotFound))
    {
        err = DocParseErrNotFound;
    }
    else
    {
        err = DocParseErrMalformedDoc;
    }

    return err;
}

DocParseErr_t otajson_SearchStringTerminateRealloc(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                const OtaMallocInterface_t * pMallocInterface,
                                char ** ppOut)
{
    DocParseErr_t err = DocParseErrNone;
    char * pOut = NULL;
    JSONStatus_t status;
    const char * value;
    size_t valueLength;
    JSONTypes_t valueType;

    if (*ppOut != NULL)
    {
        pMallocInterface->free(*ppOut);
        *ppOut = NULL;
    }

    status = JSON_SearchConst(pJson,
        jsonLength,
        key,
        keyLength,
        &value,
        &valueLength,
        &valueType);
    if (status == JSONSuccess) {
        if (valueType == JSONString)
        {
            pOut = pMallocInterface->malloc(valueLength + 1);
            if (pOut != NULL)
            {
                memcpy(pOut, value, valueLength);
                pOut[valueLength] = '\0';
                *ppOut = pOut;
            }
            else
            {
                err = DocParseErrOutOfMemory;
            }
        }
        else
        {
            err = DocParseErrFieldTypeMismatch;
        }
    }
    else if (!required && (status == JSONNotFound))
    {
        err = DocParseErrNotFound;
    }
    else
    {
        err = DocParseErrMalformedDoc;
    }

    return err;
}

DocParseErr_t otajson_SearchStringTerminateMaybeRealloc(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                const OtaMallocInterface_t * pMallocInterface,
                                char ** ppOut,
                                size_t outLength)
{
    DocParseErr_t err;
    if (outLength != 0)
    {
        assert(*ppOut != NULL);
        err = otajson_SearchStringTerminate(
            pJson, jsonLength, key, keyLength, required, *ppOut, outLength);
    }
    else
    {
        /* An output buffer length of zero means the output string is dynamically
         * allocated on the heap. */
        err = otajson_SearchStringTerminateRealloc(
            pJson, jsonLength, key, keyLength, required, pMallocInterface, ppOut);
    }

    return err;
}

DocParseErr_t Uint32FromString(const char * str, size_t strLength, uint32_t * out)
{
    DocParseErr_t err = DocParseErrNone;
    uint32_t result = 0;
    size_t i;
    for (i = 0; i < strLength; i++)
    {
        if (result > (UINT32_MAX / 10))
        {
            err = DocParseErrInvalidNumChar;
            break;
        }
        result *= 10;
        if (isdigit(str[i]))
        {
            uint32_t digit = ((uint32_t) str[i]) - '0';
            if (result > (UINT32_MAX - digit)) {
                err = DocParseErrInvalidNumChar;
                break;
            }
            result += digit;
        }
        else
        {
            err = DocParseErrInvalidNumChar;
            break;
        }
    }
    if (err == DocParseErrNone && out != NULL)
    {
        *out = result;
    }
    return err;
}

DocParseErr_t otajson_SearchUint32(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                uint32_t * out)
{
    DocParseErr_t err = DocParseErrNone;
    JSONStatus_t status;
    const char * outValue;
    size_t outValueLength;
    JSONTypes_t outType;

    status = JSON_SearchConst(pJson,
        jsonLength,
        key,
        keyLength,
        &outValue,
        &outValueLength,
        &outType);
    if (status == JSONSuccess) {
        if (outType == JSONNumber)
        {
            err = Uint32FromString(outValue, outValueLength, out);
        }
        else
        {
            err = DocParseErrFieldTypeMismatch;
        }
    }
    else if (!required && (status == JSONNotFound))
    {
        err = DocParseErrNotFound;
    }
    else
    {
        err = DocParseErrMalformedDoc;
    }

    return err;
}

DocParseErr_t otajson_SearchSignature(const char * pJson,
                                        size_t jsonLength,
                                        const char * key,
                                        size_t keyLength,
                                        Sig256_t * pSignature)
{
    DocParseErr_t err = DocParseErrNone;
    JSONStatus_t status;
    const char * value;
    size_t valueLength;
    JSONTypes_t valueType;
    Base64Status_t decodeStatus;
    size_t decodedLength;

    status = JSON_SearchConst(pJson,
        jsonLength,
        key,
        keyLength,
        &value,
        &valueLength,
        &valueType);
    if (status == JSONSuccess) {
        if (valueType == JSONString)
        {
            decodeStatus = base64Decode( pSignature->data,
                                        sizeof( pSignature->data ),
                                        &decodedLength,
                                        ( const uint8_t * ) value,
                                        valueLength );

            if( decodeStatus != Base64Success )
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
                ( void ) strncpy( pLogBuffer, value, 32 );
                pLogBuffer[ 32 ] = '\0';
                LogInfo( ( "Extracted parameter [ %s: %s... ]",
                        OTA_JsonFileSignatureKey,
                        pLogBuffer ) );

                pSignature->size = (uint16_t)decodedLength;
            }
        }
        else
        {
            err = DocParseErrFieldTypeMismatch;
        }
    }
    else if (status == JSONNotFound)
    {
        /* Note: the signature field is always optional. */
        err = DocParseErrNotFound;
    }
    else
    {
        err = DocParseErrMalformedDoc;
    }

    return err;
}

DocParseErr_t parseOtaDocument( const char * pJson,
                                uint32_t messageLength,
                                const OtaMallocInterface_t * pMallocInterface,
                                OtaFileContext_t * pFileContext )
{
    DocParseErr_t err = DocParseErrNone;
    const char * pExecutionJson = NULL;
    size_t executionJsonLength = 0;
    const char * pStatusDetailsJson = NULL;
    size_t statusDetailsJsonLength = 0;
    const char * pAfrOtaJson = NULL;
    size_t afrOtaJsonLength = 0;
    const char * pFiles0Json = NULL;
    size_t files0JsonLength = 0;

    /*
     * Parse the top level fields.
     */

    /* "clientToken", an optional string that isn't used. */
    err = otajson_SearchStringTerminate(
        pJson, messageLength, "clientToken", sizeof("clientToken") - 1, OTA_JOB_PARAM_OPTIONAL, NULL, 0);

    /* "timestamp", an optional UInt32 that isn't used. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pJson, messageLength, "timestamp", sizeof("timestamp") - 1, OTA_JOB_PARAM_OPTIONAL, NULL);
    }

    /* "execution", a required object. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pJson, messageLength, "execution", sizeof("execution") - 1, OTA_JOB_PARAM_REQUIRED, &pExecutionJson, &executionJsonLength);
    }

    /*
     * Parse the "execution" object fields.
     */

    /* "execution.jobId", a required static string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        assert(pExecutionJson != NULL);
        err = otajson_SearchStringTerminate(
            pExecutionJson, executionJsonLength, "jobId", sizeof("jobId") - 1, OTA_JOB_PARAM_REQUIRED,
            (char *)pFileContext->pJobName, pFileContext->jobNameMaxSize);
    }

    /* "execution.statusDetails", an optional object */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pExecutionJson, executionJsonLength, "statusDetails", sizeof("statusDetails") - 1, OTA_JOB_PARAM_OPTIONAL,
            &pStatusDetailsJson, &statusDetailsJsonLength);
    }

    /* "execution.jobDocument.afr_ota", a required object */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pExecutionJson, executionJsonLength, "jobDocument.afr_ota", sizeof("jobDocument.afr_ota") - 1, OTA_JOB_PARAM_REQUIRED,
            &pAfrOtaJson, &afrOtaJsonLength);
    }

    /*
     * Parse "execution.statusDetails" fields.
     */
    if (pStatusDetailsJson != NULL)
    {
        /* "execution.statusDetails.self_test", an optional string.
         * The file context interprets the presence of this string as `true`, and defaults to false. */
        if (err == DocParseErrNone || err == DocParseErrNotFound)
        {
            err = otajson_SearchStringTerminate(
                pStatusDetailsJson, statusDetailsJsonLength, "self_test", sizeof("self_test") - 1, OTA_JOB_PARAM_OPTIONAL, NULL, 0);
            if (err == DocParseErrNone)
            {
                pFileContext->isInSelfTest = true;
            }
        }

        /* "execution.statusDetails.updatedBy", an optional UInt32 */
        if (err == DocParseErrNone || err == DocParseErrNotFound)
        {
            err = otajson_SearchUint32(
                pStatusDetailsJson, statusDetailsJsonLength, "updatedBy", sizeof("updatedBy") - 1, OTA_JOB_PARAM_OPTIONAL,
                &pFileContext->updaterVersion);
        }
    }

    /*
     * Parse "execution.jobDocument.afr_ota" fields.
     */

    /* "execution.jobDocument.afr_ota.streamname", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pAfrOtaJson, afrOtaJsonLength, "streamname", sizeof("streamname") - 1, OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pStreamName, pFileContext->streamNameMaxSize);
    }

    /* "execution.jobDocument.afr_ota.protocols", a required static string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminate(
            pAfrOtaJson, afrOtaJsonLength, "protocols", sizeof("protocols") - 1, OTA_JOB_PARAM_REQUIRED,
            (char *)pFileContext->pProtocols, pFileContext->protocolMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0]", a required object in a required array. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pAfrOtaJson, afrOtaJsonLength, "files[0]", sizeof("files[0]") - 1, OTA_JOB_PARAM_REQUIRED,
            &pFiles0Json, &files0JsonLength);
    }

    /*
     * Parse "execution.jobDocument.afr_ota.files[0]" fields.
     */

    /* "execution.jobDocument.afr_ota.files[0].filepath", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, "filepath", sizeof("filepath") - 1, OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pFilePath, pFileContext->filePathMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].filesize", a required UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, "filesize", sizeof("filesize") - 1, OTA_JOB_PARAM_REQUIRED,
            &pFileContext->fileSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].fileid", a required UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, "fileid", sizeof("fileid") - 1, OTA_JOB_PARAM_REQUIRED,
            &pFileContext->serverFileID);
    }

    /* "execution.jobDocument.afr_ota.files[0].certfile", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, "certfile", sizeof("certfile") - 1, OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pCertFilepath, pFileContext->certFilePathMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].update_data_url", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, "update_data_url", sizeof("update_data_url") - 1, OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pUpdateUrlPath, pFileContext->updateUrlMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].auth_scheme", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, "auth_scheme", sizeof("auth_scheme") - 1, OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pAuthScheme, pFileContext->authSchemeMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].<signature key>", an optional base64 encoded Sig256_t. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        /* The key name for the signature is an extern global defined in the PAL layer. */
        size_t keyLength = strlen(OTA_JsonFileSignatureKey);

        err = otajson_SearchSignature(
            pFiles0Json, files0JsonLength, OTA_JsonFileSignatureKey, keyLength, pFileContext->pSignature);
    }

    /* "execution.jobDocument.afr_ota.files[0].attr", an optional UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, "attr", sizeof("attr") - 1, OTA_JOB_PARAM_OPTIONAL,
            &pFileContext->fileAttributes);
    }

    /* "execution.jobDocument.afr_ota.files[0].fileType", an optional UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, "fileType", sizeof("fileType") - 1, OTA_JOB_PARAM_OPTIONAL,
            &pFileContext->fileType);
    }

    return err;
}
#if 0
#define JOBKEY_FILES0_FILE_PATH          "filepath"                     /*!< @brief Path to store the image on the device. */
#define JOBKEY_FILES0_FILE_SIZE          "filesize"                     /*!< @brief Size of the file to be downloaded. */
#define JOBKEY_FILES0_FILE_ID            "fileid"                       /*!< @brief Used to identify the file in case of multiple file downloads. */
#define JOBKEY_FILES0_FILE_ATTRIBUTE     "attr"                         /*!< @brief Additional file attributes. */
#define JOBKEY_FILES0_FILE_CERT_NAME     "certfile"                     /*!< @brief Location of the certificate on the device to find code signing. */
#define JOBKEY_FILES0_UPDATE_DATA_URL    "update_data_url"              /*!< @brief S3 bucket presigned url to fetch the image from . */
#define JOBKEY_FILES0_AUTH_SCHEME        "auth_scheme"                  /*!< @brief Authentication scheme for downloading a the image over HTTP. */
#define JOBKEY_FILES0_FILETYPE           "fileType"                     /*!< @brief Used to identify the file in case of multi file type support. */
#endif


/* Extract the desired fields from the JSON document based on the specified document model. */

/*
 * original model
static const JsonDocParam_t otaJobDocModelParamStructure[ OTA_NUM_JOB_PARAMS ] =
{
    { OTA_JSON_CLIENT_TOKEN_KEY,    OTA_JOB_PARAM_OPTIONAL, OTA_DONT_STORE_PARAM,         OTA_DONT_STORE_PARAM,  ModelParamTypeStringInDoc },
    { OTA_JSON_TIMESTAMP_KEY,       OTA_JOB_PARAM_OPTIONAL, OTA_DONT_STORE_PARAM,         OTA_DONT_STORE_PARAM,  ModelParamTypeUInt32      },
    { OTA_JSON_EXECUTION_KEY,       OTA_JOB_PARAM_REQUIRED, OTA_DONT_STORE_PARAM,         OTA_DONT_STORE_PARAM,  ModelParamTypeObject      },
    { OTA_JSON_JOB_ID_KEY,          OTA_JOB_PARAM_REQUIRED, U16_OFFSET( OtaFileContext_t, pJobName ),            U16_OFFSET( OtaFileContext_t, jobNameMaxSize ), ModelParamTypeStringCopy},
    { OTA_JSON_STATUS_DETAILS_KEY,  OTA_JOB_PARAM_OPTIONAL, OTA_DONT_STORE_PARAM,         OTA_DONT_STORE_PARAM,  ModelParamTypeObject      },
    { OTA_JSON_SELF_TEST_KEY,       OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, isInSelfTest ),        OTA_DONT_STORE_PARAM, ModelParamTypeIdent},
    { OTA_JSON_UPDATED_BY_KEY,      OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, updaterVersion ),      OTA_DONT_STORE_PARAM, ModelParamTypeUInt32},
    { OTA_JSON_JOB_DOC_KEY,         OTA_JOB_PARAM_REQUIRED, OTA_DONT_STORE_PARAM,         OTA_DONT_STORE_PARAM,  ModelParamTypeObject      },
    { OTA_JSON_OTA_UNIT_KEY,        OTA_JOB_PARAM_REQUIRED, OTA_DONT_STORE_PARAM,         OTA_DONT_STORE_PARAM,  ModelParamTypeObject      },
    { OTA_JSON_STREAM_NAME_KEY,     OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, pStreamName ),         U16_OFFSET( OtaFileContext_t, streamNameMaxSize ), ModelParamTypeStringCopy},
    { OTA_JSON_PROTOCOLS_KEY,       OTA_JOB_PARAM_REQUIRED, U16_OFFSET( OtaFileContext_t, pProtocols ),          U16_OFFSET( OtaFileContext_t, protocolMaxSize ), ModelParamTypeArrayCopy},
    { OTA_JSON_FILE_PATH_KEY,       OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, pFilePath ),           U16_OFFSET( OtaFileContext_t, filePathMaxSize ), ModelParamTypeStringCopy},
    { OTA_JSON_FILE_SIZE_KEY,       OTA_JOB_PARAM_REQUIRED, U16_OFFSET( OtaFileContext_t, fileSize ),            OTA_DONT_STORE_PARAM, ModelParamTypeUInt32},
    { OTA_JSON_FILE_ID_KEY,         OTA_JOB_PARAM_REQUIRED, U16_OFFSET( OtaFileContext_t, serverFileID ),        OTA_DONT_STORE_PARAM, ModelParamTypeUInt32},
    { OTA_JSON_FILE_CERT_NAME_KEY,  OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, pCertFilepath ),       U16_OFFSET( OtaFileContext_t, certFilePathMaxSize ), ModelParamTypeStringCopy},
    { OTA_JSON_UPDATE_DATA_URL_KEY, OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, pUpdateUrlPath ),      U16_OFFSET( OtaFileContext_t, updateUrlMaxSize ), ModelParamTypeStringCopy},
    { OTA_JSON_AUTH_SCHEME_KEY,     OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, pAuthScheme ),         U16_OFFSET( OtaFileContext_t, authSchemeMaxSize ), ModelParamTypeStringCopy},
    { OTA_JsonFileSignatureKey,     OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, pSignature ),          OTA_DONT_STORE_PARAM, ModelParamTypeSigBase64},
    { OTA_JSON_FILE_ATTRIBUTE_KEY,  OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, fileAttributes ),      OTA_DONT_STORE_PARAM, ModelParamTypeUInt32},
    { OTA_JSON_FILETYPE_KEY,        OTA_JOB_PARAM_OPTIONAL, U16_OFFSET( OtaFileContext_t, fileType ),            OTA_DONT_STORE_PARAM, ModelParamTypeUInt32}
};
 */

/* top level */
#define JOBKEY_CLIENT_TOKEN       "clientToken"                                              /*!< @brief Client token. */
#define JOBKEY_TIMESTAMP          "timestamp"                                                /*!< @brief Used to calculate timeout and time spent on the operation. */
#define JOBKEY_EXECUTION          "execution"                                                /*!< @brief Contains job execution parameters . */

/* "execution." */
#define JOBKEY_EXECUTION_JOB_ID             "jobId"          /*!< @brief Name of the job. */
#define JOBKEY_EXECUTION_STATUS_DETAILS     "statusDetails"  /*!< @brief Current status of the job. */
#define JOBKEY_EXECUTION_JOB_DOC_AFR_OTA    "jobDocument.afr_ota"    /*!< @brief Parameters that specify the nature of the job. */

/* "execution.statusDetails." */
#define JOBKEY_EXECUTION_STATUS_DETAILS_SELF_TEST          "self_test" /*!< @brief Specifies if the platform and service is is selftest. */
#define JOBKEY_EXECUTION_STATUS_DETAILS_UPDATED_BY         "updatedBy" /*!< @brief Parameter to specify update status. */

/* "execution.jobDocument.afr_ota." */
#define JOBKEY_AFROTA_PROTOCOLS          "protocols"       /*!< @brief Protocols over which the download can take place. */
#define JOBKEY_AFROTA_FILES0             "files[0]"        /*!< @brief Parameters for specifying file configurations. */
#define JOBKEY_AFROTA_STREAM_NAME        "streamname"      /*!< @brief Name of the stream used for download. */

/* "execution.jobDocument.afr_ota.files[0]." */
#define JOBKEY_FILES0_FILE_PATH          "filepath"                     /*!< @brief Path to store the image on the device. */
#define JOBKEY_FILES0_FILE_SIZE          "filesize"                     /*!< @brief Size of the file to be downloaded. */
#define JOBKEY_FILES0_FILE_ID            "fileid"                       /*!< @brief Used to identify the file in case of multiple file downloads. */
#define JOBKEY_FILES0_FILE_ATTRIBUTE     "attr"                         /*!< @brief Additional file attributes. */
#define JOBKEY_FILES0_FILE_CERT_NAME     "certfile"                     /*!< @brief Location of the certificate on the device to find code signing. */
#define JOBKEY_FILES0_UPDATE_DATA_URL    "update_data_url"              /*!< @brief S3 bucket presigned url to fetch the image from . */
#define JOBKEY_FILES0_AUTH_SCHEME        "auth_scheme"                  /*!< @brief Authentication scheme for downloading a the image over HTTP. */
#define JOBKEY_FILES0_FILETYPE           "fileType"                     /*!< @brief Used to identify the file in case of multi file type support. */


#define JOBDOCCONSTKEY( tok ) tok, sizeof(tok) - 1


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
    if ( JSON_Validate( pJson, messageLength ) != JSONSuccess ) {
        return DocParseErr_InvalidJSONBuffer;
    }

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

