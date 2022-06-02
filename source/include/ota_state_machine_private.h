#ifndef OTA_STATE_MACHINE_PRIVATE_H
#define OTA_STATE_MACHINE_PRIVATE_H

#include "ota.h"

/**
 * @brief OTA event handler definition.
 */
typedef OtaErr_t ( * OtaEventHandler_t )( const OtaEventData_t * pEventMsg );

/**
 * @ingroup ota_datatypes_structs
 * @brief OTA Agent state table entry.
 * */

typedef struct OtaStateTableEntry
{
    OtaState_t currentState;   /**< Current state of the agent. */
    OtaEvent_t eventId;        /**< Event corresponding to the action. */
    OtaEventHandler_t handler; /**< Handler to invoke the next action. */
    OtaState_t nextState;      /**< New state to be triggered*/
} OtaStateTableEntry_t;

bool findStateTransitionForEvent( OtaStateTableEntry_t * pTransitionTable,
                                  size_t tableCount,
                                  OtaState_t currentState,
                                  OtaEvent_t eventId,
                                  OtaEventHandler_t * pActionHandler,
                                  OtaState_t * pNextState);


/* OTA state event handler functions. */

OtaErr_t startHandler( const OtaEventData_t * pEventData );           /*!< Start timers and initiate request for job document. */
OtaErr_t requestJobHandler( const OtaEventData_t * pEventData );      /*!< Initiate a request for a job. */
OtaErr_t processJobHandler( const OtaEventData_t * pEventData );      /*!< Update file context from job document. */
OtaErr_t inSelfTestHandler( const OtaEventData_t * pEventData );      /*!< Handle self test. */
OtaErr_t initFileHandler( const OtaEventData_t * pEventData );        /*!< Initialize and handle file transfer. */
OtaErr_t processDataHandler( const OtaEventData_t * pEventData );     /*!< Process incoming data blocks. */
OtaErr_t requestDataHandler( const OtaEventData_t * pEventData );     /*!< Request for data blocks. */
OtaErr_t shutdownHandler( const OtaEventData_t * pEventData );        /*!< Shutdown OTA and cleanup. */
OtaErr_t closeFileHandler( const OtaEventData_t * pEventData );       /*!< Close file opened for download. */
OtaErr_t userAbortHandler( const OtaEventData_t * pEventData );       /*!< Handle user interrupt to abort task. */
OtaErr_t suspendHandler( const OtaEventData_t * pEventData );         /*!< Handle suspend event for OTA agent. */
OtaErr_t resumeHandler( const OtaEventData_t * pEventData );          /*!< Resume from a suspended state. */
OtaErr_t jobNotificationHandler( const OtaEventData_t * pEventData ); /*!< Upon receiving a new job document cancel current job if present and initiate new download. */
void executeHandler( uint32_t index,
                     const OtaEventMsg_t * const pEventMsg );         /*!< Execute the handler for selected index from the transition table. */

bool findStateTransitionForOtaEvent( OtaState_t currentState,
                                     OtaEvent_t eventId,
                                     OtaEventHandler_t * pActionHandler,
                                     OtaState_t * pNextState);

#endif /* OTA_STATE_MACHINE_PRIVATE_H */
