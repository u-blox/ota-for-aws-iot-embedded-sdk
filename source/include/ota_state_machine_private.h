#ifndef OTA_STATE_MACHINE_PRIVATE_H
#define OTA_STATE_MACHINE_PRIVATE_H

#include "ota.h"

typedef enum OtaStateMachineActions
{
    OtaActionStart,
    OtaActionRequestJob,
    OtaActionProcessJob,
    OtaActionInSelfTest,
    OtaActionInitFile,
    OtaActionRequestData,
    OtaActionProcessData,
    OtaActionJobNotification,
    OtaActionCloseFile,
    OtaActionResume,
    OtaActionSuspend,
    OtaActionUserAbort,
    OtaActionShutdown
} OtaStateMachineActions_t;

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
                                  uint32_t tableCount,
                                  OtaState_t currentState,
                                  OtaEvent_t eventId,
                                  OtaEventHandler_t * pActionHandler,
                                  OtaState_t * pNextState);


#endif /* OTA_STATE_MACHINE_PRIVATE_H */
