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

DocParseErr_t otajson_SearchField(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                JSONTypes_t expectedType,
                                const char ** ppValue,
                                size_t * pValueLength)
{
    DocParseErr_t err = DocParseErrNone;
    JSONStatus_t status;
    const char * pValue;
    size_t valueLength;
    JSONTypes_t valueType;

    status = JSON_SearchConst(pJson,
        jsonLength,
        key,
        keyLength,
        &pValue,
        &valueLength,
        &valueType);
    if (status == JSONSuccess) {
        if (valueType == expectedType)
        {
            *ppValue = pValue;
            *pValueLength = valueLength;
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

DocParseErr_t otajson_SearchObject(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                const char ** ppOut,
                                size_t * pOutLength)
{
    return otajson_SearchField(pJson, jsonLength, key, keyLength, required, JSONObject, ppOut, pOutLength);
}

DocParseErr_t otajson_SearchStringTerminate(const char * pJson,
                                size_t jsonLength,
                                const char * key,
                                size_t keyLength,
                                bool required,
                                char * pOut,
                                size_t outLength)
{
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;

    err = otajson_SearchField(pJson, jsonLength, key, keyLength, required, JSONString, &pValue, &valueLength);
    if (err == DocParseErrNone && pOut != NULL)
    {
        /* The output is expecting a NUL terminated string, so the raw value must be at least one byte smaller. */
        if (valueLength < outLength)
        {
            memcpy(pOut, pValue, valueLength);
            pOut[valueLength] = '\0';
        }
        else
        {
            err = DocParseErrUserBufferInsuffcient;
        }
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
    const char * pValue;
    size_t valueLength;

    if (*ppOut != NULL)
    {
        pMallocInterface->free(*ppOut);
        *ppOut = NULL;
    }

    err = otajson_SearchField(pJson, jsonLength, key, keyLength, required, JSONString, &pValue, &valueLength);
    if (err == DocParseErrNone)
    {
        pOut = pMallocInterface->malloc(valueLength + 1);
        if (pOut != NULL)
        {
            memcpy(pOut, pValue, valueLength);
            pOut[valueLength] = '\0';
            *ppOut = pOut;
        }
        else
        {
            err = DocParseErrOutOfMemory;
        }
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
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;

    err = otajson_SearchField(pJson, jsonLength, key, keyLength, required, JSONNumber, &pValue, &valueLength);

    if (err == DocParseErrNone)
    {
        err = Uint32FromString(pValue, valueLength, out);
    }

    return err;
}

DocParseErr_t otajson_SearchSignature(const char * pJson,
                                        size_t jsonLength,
                                        const char * key,
                                        size_t keyLength,
                                        Sig256_t * pSignature)
{
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;
    Base64Status_t decodeStatus;
    size_t decodedLength;

    /* Note: signatures are always optional. */
    err = otajson_SearchField(
        pJson, jsonLength, key, keyLength, OTA_JOB_PARAM_OPTIONAL, JSONString, &pValue, &valueLength);

    if (err == DocParseErrNone)
    {
        decodeStatus = base64Decode( pSignature->data,
                                    sizeof( pSignature->data ),
                                    &decodedLength,
                                    ( const uint8_t * ) pValue,
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
            ( void ) strncpy( pLogBuffer, pValue, 32 );
            pLogBuffer[ 32 ] = '\0';
            LogInfo( ( "Extracted parameter [ %s: %s... ]",
                    OTA_JsonFileSignatureKey,
                    pLogBuffer ) );

            pSignature->size = (uint16_t)decodedLength;
        }
    }

    return err;
}

DocParseErr_t otajson_SearchProtocols(const char * pJson,
                                        size_t jsonLength,
                                        const char * key,
                                        size_t keyLength,
                                        bool * pSupportsMqtt,
                                        bool * pSupportsHttp)
{
    DocParseErr_t err;
    const char * pProtocols;
    size_t protocolsLength;

    JSONStatus_t status = JSONSuccess;
    JSONPair_t pair;
    size_t start = 0;
    size_t next = 0;

    bool supportsMqtt = false;
    bool supportsHttp = false;

    /* Note: the protocol array is always required. */
    err = otajson_SearchField(
        pJson, jsonLength, key, keyLength, OTA_JOB_PARAM_REQUIRED, JSONArray, &pProtocols, &protocolsLength);

    if (err == DocParseErrNone)
    {
        while (status == JSONSuccess)
        {
            status = JSON_Iterate(pProtocols, protocolsLength, &start, &next, &pair);
            if ( status != JSONSuccess )
            {
                break;
            }
            else
            {
                assert(pair.key == NULL);
                if (pair.valueLength == CONST_STRLEN("MQTT") && strncmp(pair.value, "MQTT", CONST_STRLEN("MQTT")) == 0)
                {
                    supportsMqtt = true;
                }
                else if (pair.valueLength == CONST_STRLEN("HTTP") && strncmp(pair.value, "HTTP", CONST_STRLEN("HTTP")) == 0)
                {
                    supportsHttp = true;
                }
            }
        }

        /* JSONNotFound indicates the successful end of the iteration. */
        if (status == JSONNotFound)
        {
            *pSupportsMqtt = supportsMqtt;
            *pSupportsHttp = supportsHttp;
        }
        else
        {
            err = DocParseErrMalformedDoc;
        }
    }

    return err;
}


/*
 * String constants for parsing OTA job documents.
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
#define JOBKEY_STATUS_DETAILS_SELF_TEST          "self_test" /*!< @brief Specifies if the platform and service is is selftest. */
#define JOBKEY_STATUS_DETAILS_UPDATED_BY         "updatedBy" /*!< @brief Parameter to specify update status. */

/* "execution.jobDocument.afr_ota." */
#define JOBKEY_AFROTA_PROTOCOLS          "protocols"       /*!< @brief Protocols over which the download can take place. */
#define JOBKEY_AFROTA_FILES0             "files[0]"        /*!< @brief Parameters for specifying file configurations. */
#define JOBKEY_AFROTA_STREAM_NAME        "streamname"      /*!< @brief Name of the stream used for download. */

/* "execution.jobDocument.afr_ota.files[0]." */
#define JOBKEY_FILES0_FILE_PATH          "filepath"                     /*!< @brief Path to store the image on the device. */
#define JOBKEY_FILES0_FILE_SIZE          "filesize"                     /*!< @brief Size of the file to be downloaded. */
#define JOBKEY_FILES0_FILE_ID            "fileid"                       /*!< @brief Used to identify the file in case of multiple file downloads. */
#define JOBKEY_FILES0_FILE_ATTRIBUTES    "attr"                         /*!< @brief Additional file attributes. */
#define JOBKEY_FILES0_FILE_CERT_FILE     "certfile"                     /*!< @brief Location of the certificate on the device to find code signing. */
#define JOBKEY_FILES0_UPDATE_DATA_URL    "update_data_url"              /*!< @brief S3 bucket presigned url to fetch the image from . */
#define JOBKEY_FILES0_AUTH_SCHEME        "auth_scheme"                  /*!< @brief Authentication scheme for downloading a the image over HTTP. */
#define JOBKEY_FILES0_FILETYPE           "fileType"                     /*!< @brief Used to identify the file in case of multi file type support. */

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

    #define CONST_KEY( tok ) tok, CONST_STRLEN(tok)

    /*
     * Parse the top level fields.
     */

    /* "clientToken", an optional string that isn't used. */
    err = otajson_SearchStringTerminate(
        pJson, messageLength, CONST_KEY(JOBKEY_CLIENT_TOKEN), OTA_JOB_PARAM_OPTIONAL, NULL, 0);

    /* "timestamp", an optional UInt32 that isn't used. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pJson, messageLength, CONST_KEY(JOBKEY_TIMESTAMP), OTA_JOB_PARAM_OPTIONAL, NULL);
    }

    /* "execution", a required object. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pJson, messageLength, CONST_KEY(JOBKEY_EXECUTION), OTA_JOB_PARAM_REQUIRED, &pExecutionJson, &executionJsonLength);
    }

    /*
     * Parse the "execution" object fields.
     */

    /* "execution.jobId", a required static string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        assert(pExecutionJson != NULL);
        err = otajson_SearchStringTerminate(
            pExecutionJson, executionJsonLength, CONST_KEY(JOBKEY_EXECUTION_JOB_ID), OTA_JOB_PARAM_REQUIRED,
            (char *)pFileContext->pJobName, pFileContext->jobNameMaxSize);
    }

    /* "execution.statusDetails", an optional object */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pExecutionJson, executionJsonLength, CONST_KEY(JOBKEY_EXECUTION_STATUS_DETAILS), OTA_JOB_PARAM_OPTIONAL,
            &pStatusDetailsJson, &statusDetailsJsonLength);
    }

    /* "execution.jobDocument.afr_ota", a required object */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pExecutionJson, executionJsonLength, CONST_KEY(JOBKEY_EXECUTION_JOB_DOC_AFR_OTA), OTA_JOB_PARAM_REQUIRED,
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
                pStatusDetailsJson, statusDetailsJsonLength, CONST_KEY(JOBKEY_STATUS_DETAILS_SELF_TEST), OTA_JOB_PARAM_OPTIONAL, NULL, 0);
            if (err == DocParseErrNone)
            {
                pFileContext->isInSelfTest = true;
            }
        }

        /* "execution.statusDetails.updatedBy", an optional UInt32 */
        if (err == DocParseErrNone || err == DocParseErrNotFound)
        {
            err = otajson_SearchUint32(
                pStatusDetailsJson, statusDetailsJsonLength, CONST_KEY(JOBKEY_STATUS_DETAILS_UPDATED_BY), OTA_JOB_PARAM_OPTIONAL,
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
            pAfrOtaJson, afrOtaJsonLength, CONST_KEY(JOBKEY_AFROTA_STREAM_NAME), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pStreamName, pFileContext->streamNameMaxSize);
    }

    /* "execution.jobDocument.afr_ota.protocols", a required array of strings. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        /* "protocols" is an array that can contain the strings "MQTT" and "HTTP". */
        err = otajson_SearchProtocols(
            pAfrOtaJson, afrOtaJsonLength, CONST_KEY(JOBKEY_AFROTA_PROTOCOLS),
            &pFileContext->jobSupportsMqtt, &pFileContext->jobSupportsHttp);
    }

    /* "execution.jobDocument.afr_ota.files[0]", a required object in a required array. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchObject(
            pAfrOtaJson, afrOtaJsonLength, CONST_KEY(JOBKEY_AFROTA_FILES0), OTA_JOB_PARAM_REQUIRED,
            &pFiles0Json, &files0JsonLength);
    }

    /*
     * Parse "execution.jobDocument.afr_ota.files[0]" fields.
     */

    /* "execution.jobDocument.afr_ota.files[0].filepath", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_PATH), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pFilePath, pFileContext->filePathMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].filesize", a required UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_SIZE), OTA_JOB_PARAM_REQUIRED,
            &pFileContext->fileSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].fileid", a required UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_ID), OTA_JOB_PARAM_REQUIRED,
            &pFileContext->serverFileID);
    }

    /* "execution.jobDocument.afr_ota.files[0].certfile", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_CERT_FILE), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pCertFilepath, pFileContext->certFilePathMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].update_data_url", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_UPDATE_DATA_URL), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pUpdateUrlPath, pFileContext->updateUrlMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].auth_scheme", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_AUTH_SCHEME), OTA_JOB_PARAM_OPTIONAL,
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
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_ATTRIBUTES), OTA_JOB_PARAM_OPTIONAL,
            &pFileContext->fileAttributes);
    }

    /* "execution.jobDocument.afr_ota.files[0].fileType", an optional UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_SearchUint32(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILETYPE), OTA_JOB_PARAM_OPTIONAL,
            &pFileContext->fileType);
    }

    #undef CONST_KEY

    /* DocParseErrNotFound here just means an optional field was missing. */
    if (err == DocParseErrNotFound)
    {
        err = DocParseErrNone;
    }

    return err;
}


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

