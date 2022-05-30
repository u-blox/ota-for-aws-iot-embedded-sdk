#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "core_json.h"
#include "ota.h"
#include "ota_base64_private.h"
#include "ota_parse_job_private.h"


DocParseErr_t otajson_getFieldValue(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
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
        pKey,
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

DocParseErr_t otajson_parseFieldObject(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
                                size_t keyLength,
                                bool required,
                                const char ** ppOut,
                                size_t * pOutLength)
{
    return otajson_getFieldValue(pJson, jsonLength, pKey, keyLength, required, JSONObject, ppOut, pOutLength);
}

DocParseErr_t otajson_parseFieldStringTerminate(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
                                size_t keyLength,
                                bool required,
                                char * pOut,
                                size_t outLength)
{
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;

    err = otajson_getFieldValue(pJson, jsonLength, pKey, keyLength, required, JSONString, &pValue, &valueLength);
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

DocParseErr_t otajson_parseFieldStringTerminateRealloc(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
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

    err = otajson_getFieldValue(pJson, jsonLength, pKey, keyLength, required, JSONString, &pValue, &valueLength);
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

DocParseErr_t otajson_parseFieldStringTerminateMaybeRealloc(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
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
        err = otajson_parseFieldStringTerminate(
            pJson, jsonLength, pKey, keyLength, required, *ppOut, outLength);
    }
    else
    {
        /* An output buffer length of zero means the output string is dynamically
         * allocated on the heap. */
        err = otajson_parseFieldStringTerminateRealloc(
            pJson, jsonLength, pKey, keyLength, required, pMallocInterface, ppOut);
    }

    return err;
}

DocParseErr_t otajson_uint32FromString(const char * str, size_t strLength, uint32_t * out)
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

DocParseErr_t otajson_parseFieldUint32(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
                                size_t keyLength,
                                bool required,
                                uint32_t * out)
{
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;

    err = otajson_getFieldValue(pJson, jsonLength, pKey, keyLength, required, JSONNumber, &pValue, &valueLength);

    if (err == DocParseErrNone)
    {
        err = otajson_uint32FromString(pValue, valueLength, out);
    }

    return err;
}

bool otajson_isoctaldigit(char c)
{
    return isdigit(c) && c != '8' && c != '9';
}

DocParseErr_t otajson_uint32FromStringLikeStrtoul(const char * str, size_t strLength, uint32_t * out)
{
    DocParseErr_t err = DocParseErrNone;
    uint32_t result = 0;
    size_t i;
    uint32_t base;
    uint32_t uintMaxOverBase;
    const char * pDigits;
    size_t digitsLength;
    uint32_t digit;

    /* Skip leading whitespace. */
    for (i = 0; i < strLength; i++) {
        if (!isspace(str[i]))
        {
            break;
        }
    }

    /* Interpret sign. */
    if (i < strLength)
    {
        if (str[i] == '+')
        {
            /* Skip a plus sign. */
            i++;
        }
        else if (str[i] == '-')
        {
            /* Negative numbers are not allowed */
            err = DocParseErrInvalidNumChar;
        }
    }
    else
    {
        /* We never got to the digits. */
        err = DocParseErrInvalidNumChar;
    }

    /* Examine the first digit. */
    if (err == DocParseErrNone)
    {
        if (i < strLength && isdigit(str[i]))
        {
            if (str[i] == '0')
            {
                /* This number could be zero, or an octal number, or a hexidecimal number. */
                i++;

                if (i < strLength)
                {
                    /* This character could be an octal digit, an 'X', an 'x' or another non-digit. */
                    if (isdigit(str[i]))
                    {
                        /* octal (will check for valid octal digits below) */
                        base = 8;
                        pDigits = &str[i];
                        digitsLength = strLength - i;
                    }
                    else if (str[i] == 'X' || str[i] == 'x')
                    {
                        /* hexidecimal */
                        i++;
                        base = 16;
                        pDigits = &str[i];
                        digitsLength = strLength - i;
                    }
                    else
                    {
                        /* There is one digit and it's zero. Fall through to the base 10 parser. */
                        base = 10;
                        pDigits = &str[i];
                        digitsLength = 1;
                    }
                }
                else
                {
                    /* There is one digit and it's zero. Fall through to the base 10 parser. */
                    base = 10;
                    pDigits = &str[i];
                    digitsLength = 1;
                }
            }
            else
            {
                /* A non-zero leading digit must be base 10. */
                base = 10;
                pDigits = &str[i];
                digitsLength = strLength - i;
            }
        }
        else
        {
            /* We never got to the digits. */
            err = DocParseErrInvalidNumChar;
        }
    }

    /* Compute the result by iterating through the digits. */
    if (err == DocParseErrNone)
    {
        assert(base == 8 || base == 10 || base == 16);

        /* Prevent overflow by knowing when result > (UINT_MAX / base).
         * Compute at compile time to avoid runtime divisions. */
        if (base == 8)
        {
            uintMaxOverBase = (UINT32_MAX / 8);
        }
        else if (base == 10)
        {
            uintMaxOverBase = (UINT32_MAX / 10);
        }
        else
        {
            assert(base == 16);
            uintMaxOverBase = (UINT32_MAX / 16);
        }

        for (i = 0; i < digitsLength; i++)
        {
            /* Check for the end of the digits.
             * To match strtoul, characters after the first non-digit are ignored. */
            if (base == 16 && !isxdigit(pDigits[i]))
            {
                break;
            }
            else if (base == 10 && !isdigit(pDigits[i]))
            {
                break;
            }
            else if (!otajson_isoctaldigit(pDigits[i]))
            {
                assert(base == 8);
                break;
            }

            /* Convert the current digit to a uint. */
            if (isdigit(pDigits[i]))
            {
                digit = ((uint32_t) pDigits[i]) - '0';
            }
            else
            {
                assert(base == 16);
                if (pDigits[i] >= 'A' && pDigits[i] <= 'F')
                {
                    digit = ((uint32_t) pDigits[i]) - 'A' + 10;
                }
                else
                {
                    assert(pDigits[i] >= 'a' && pDigits[i] <= 'f');
                    digit = ((uint32_t) pDigits[i]) - 'a' + 10;
                }
            }

            /* Add the current digit into the result. */
            if (result > uintMaxOverBase)
            {
                /* Overflow. */
                err = DocParseErrInvalidNumChar;
            }
            else
            {
                result *= base;
                if (result > (UINT32_MAX - digit))
                {
                    /* Overflow. */
                    err = DocParseErrInvalidNumChar;
                }
                else
                {
                    result += digit;
                }
            }
        }

        if (i == 0)
        {
            /* No digits found at all. */
            err = DocParseErrInvalidNumChar;
        }
        else if (base == 8 && i < digitsLength && isdigit(pDigits[i]))
        {
            /* A non-octal digit after a set of octal digits is invalid. */
            err = DocParseErrInvalidNumChar;
        }
    }

    if (err == DocParseErrNone && out != NULL)
    {
        *out = result;
    }
    return err;
}

DocParseErr_t otajson_parseFieldUint32InString(const char * pJson,
                                size_t jsonLength,
                                const char * pKey,
                                size_t keyLength,
                                bool required,
                                uint32_t * out)
{
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;

    err = otajson_getFieldValue(pJson, jsonLength, pKey, keyLength, required, JSONString, &pValue, &valueLength);

    if (err == DocParseErrNone)
    {
        /*
         * Previous implementations used strtoul to parse this string. This function must match its
         * behavior.
         */
        err = otajson_uint32FromStringLikeStrtoul(pValue, valueLength, out);
    }

    return err;
}

DocParseErr_t otajson_parseFieldSignature(const char * pJson,
                                        size_t jsonLength,
                                        const char * pKey,
                                        size_t keyLength,
                                        Sig256_t * pSignature)
{
    DocParseErr_t err;
    const char * pValue;
    size_t valueLength;
    Base64Status_t decodeStatus;
    size_t decodedLength;

    /* Note: signatures are always optional. */
    err = otajson_getFieldValue(
        pJson, jsonLength, pKey, keyLength, OTA_JOB_PARAM_OPTIONAL, JSONString, &pValue, &valueLength);

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

DocParseErr_t otajson_parseFieldProtocols(const char * pJson,
                                        size_t jsonLength,
                                        const char * pKey,
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
    err = otajson_getFieldValue(
        pJson, jsonLength, pKey, keyLength, OTA_JOB_PARAM_REQUIRED, JSONArray, &pProtocols, &protocolsLength);

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
    err = otajson_parseFieldStringTerminate(
        pJson, messageLength, CONST_KEY(JOBKEY_CLIENT_TOKEN), OTA_JOB_PARAM_OPTIONAL, NULL, 0);

    /* "timestamp", an optional UInt32 that isn't used. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldUint32(
            pJson, messageLength, CONST_KEY(JOBKEY_TIMESTAMP), OTA_JOB_PARAM_OPTIONAL, NULL);
    }

    /* "execution", a required object. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldObject(
            pJson, messageLength, CONST_KEY(JOBKEY_EXECUTION), OTA_JOB_PARAM_REQUIRED, &pExecutionJson, &executionJsonLength);
    }

    /*
     * Parse the "execution" object fields.
     */

    /* "execution.jobId", a required static string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        assert(pExecutionJson != NULL);
        err = otajson_parseFieldStringTerminate(
            pExecutionJson, executionJsonLength, CONST_KEY(JOBKEY_EXECUTION_JOB_ID), OTA_JOB_PARAM_REQUIRED,
            (char *)pFileContext->pJobName, pFileContext->jobNameMaxSize);
    }

    /* "execution.statusDetails", an optional object */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldObject(
            pExecutionJson, executionJsonLength, CONST_KEY(JOBKEY_EXECUTION_STATUS_DETAILS), OTA_JOB_PARAM_OPTIONAL,
            &pStatusDetailsJson, &statusDetailsJsonLength);
    }

    /* "execution.jobDocument.afr_ota", a required object */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldObject(
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
            err = otajson_parseFieldStringTerminate(
                pStatusDetailsJson, statusDetailsJsonLength, CONST_KEY(JOBKEY_STATUS_DETAILS_SELF_TEST), OTA_JOB_PARAM_OPTIONAL, NULL, 0);
            if (err == DocParseErrNone)
            {
                pFileContext->isInSelfTest = true;
            }
        }

        /* "execution.statusDetails.updatedBy", an optional UInt32 */
        if (err == DocParseErrNone || err == DocParseErrNotFound)
        {
            err = otajson_parseFieldUint32(
                pStatusDetailsJson, statusDetailsJsonLength, CONST_KEY(JOBKEY_STATUS_DETAILS_UPDATED_BY), OTA_JOB_PARAM_OPTIONAL,
                &pFileContext->updaterVersion);

            /* "updatedBy" is for some reason sometimes wrapped in a string. */
            if (err == DocParseErrFieldTypeMismatch)
            {
                err = otajson_parseFieldUint32InString(
                    pStatusDetailsJson, statusDetailsJsonLength, CONST_KEY(JOBKEY_STATUS_DETAILS_UPDATED_BY), OTA_JOB_PARAM_OPTIONAL,
                    &pFileContext->updaterVersion);
            }
        }
    }

    /*
     * Parse "execution.jobDocument.afr_ota" fields.
     */

    /* "execution.jobDocument.afr_ota.streamname", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldStringTerminateMaybeRealloc(
            pAfrOtaJson, afrOtaJsonLength, CONST_KEY(JOBKEY_AFROTA_STREAM_NAME), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pStreamName, pFileContext->streamNameMaxSize);
    }

    /* "execution.jobDocument.afr_ota.protocols", a required array of strings. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        /* "protocols" is an array that can contain the strings "MQTT" and "HTTP". */
        err = otajson_parseFieldProtocols(
            pAfrOtaJson, afrOtaJsonLength, CONST_KEY(JOBKEY_AFROTA_PROTOCOLS),
            &pFileContext->jobSupportsMqtt, &pFileContext->jobSupportsHttp);
    }

    /* "execution.jobDocument.afr_ota.files[0]", a required object in a required array. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldObject(
            pAfrOtaJson, afrOtaJsonLength, CONST_KEY(JOBKEY_AFROTA_FILES0), OTA_JOB_PARAM_REQUIRED,
            &pFiles0Json, &files0JsonLength);
    }

    /*
     * Parse "execution.jobDocument.afr_ota.files[0]" fields.
     */

    /* "execution.jobDocument.afr_ota.files[0].filepath", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_PATH), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pFilePath, pFileContext->filePathMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].filesize", a required UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldUint32(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_SIZE), OTA_JOB_PARAM_REQUIRED,
            &pFileContext->fileSize);

        if (err == DocParseErrFieldTypeMismatch)
        {
            /* "filesize" is for some reason sometimes wrapped in a string. */
            err = otajson_parseFieldUint32InString(
                pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_SIZE), OTA_JOB_PARAM_REQUIRED,
                &pFileContext->fileSize);
        }
    }

    /* "execution.jobDocument.afr_ota.files[0].fileid", a required UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldUint32(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_ID), OTA_JOB_PARAM_REQUIRED,
            &pFileContext->serverFileID);
    }

    /* "execution.jobDocument.afr_ota.files[0].certfile", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_CERT_FILE), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pCertFilepath, pFileContext->certFilePathMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].update_data_url", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_UPDATE_DATA_URL), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pUpdateUrlPath, pFileContext->updateUrlMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].auth_scheme", an optional possibly dynamic string. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldStringTerminateMaybeRealloc(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_AUTH_SCHEME), OTA_JOB_PARAM_OPTIONAL,
            pMallocInterface, (char **)&pFileContext->pAuthScheme, pFileContext->authSchemeMaxSize);
    }

    /* "execution.jobDocument.afr_ota.files[0].<signature key>", an optional base64 encoded Sig256_t. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        /* The key name for the signature is an extern global defined in the PAL layer. */
        size_t keyLength = strlen(OTA_JsonFileSignatureKey);

        err = otajson_parseFieldSignature(
            pFiles0Json, files0JsonLength, OTA_JsonFileSignatureKey, keyLength, pFileContext->pSignature);
    }

    /* "execution.jobDocument.afr_ota.files[0].attr", an optional UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldUint32(
            pFiles0Json, files0JsonLength, CONST_KEY(JOBKEY_FILES0_FILE_ATTRIBUTES), OTA_JOB_PARAM_OPTIONAL,
            &pFileContext->fileAttributes);
    }

    /* "execution.jobDocument.afr_ota.files[0].fileType", an optional UInt32. */
    if (err == DocParseErrNone || err == DocParseErrNotFound)
    {
        err = otajson_parseFieldUint32(
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
