#include "ota_state_machine_private.h"


bool findStateTransitionForEvent( OtaStateTableEntry_t * pTransitionTable,
                                  size_t tableCount,
                                  OtaState_t currentState,
                                  OtaEvent_t eventId,
                                  OtaEventHandler_t * pActionHandler,
                                  OtaState_t * pNextState)
{
    bool found = false;
    size_t i;
    for( i = 0; i < tableCount; i++ )
    {
        if( ( ( pTransitionTable[ i ].currentState == currentState ) ||
              ( pTransitionTable[ i ].currentState == OtaAgentStateAll ) ) &&
              ( pTransitionTable[ i ].eventId == eventId ) )
        {
            found = true;
            *pActionHandler = pTransitionTable[ i ].handler;
            *pNextState = pTransitionTable[ i ].nextState;
        }
    }

    return found;
}

/**
 * @brief Transition table for the OTA state machine.
 */
static OtaStateTableEntry_t otaTransitionTable[] =
{
    /*STATE ,                              EVENT ,                               ACTION ,               NEXT STATE                         */
    { OtaAgentStateReady,               OtaAgentEventStart,               startHandler,           OtaAgentStateRequestingJob       },
    { OtaAgentStateRequestingJob,       OtaAgentEventRequestJobDocument,  requestJobHandler,      OtaAgentStateWaitingForJob       },
    { OtaAgentStateRequestingJob,       OtaAgentEventRequestTimer,        requestJobHandler,      OtaAgentStateWaitingForJob       },
    { OtaAgentStateWaitingForJob,       OtaAgentEventReceivedJobDocument, processJobHandler,      OtaAgentStateCreatingFile        },
    { OtaAgentStateCreatingFile,        OtaAgentEventStartSelfTest,       inSelfTestHandler,      OtaAgentStateWaitingForJob       },
    { OtaAgentStateCreatingFile,        OtaAgentEventCreateFile,          initFileHandler,        OtaAgentStateRequestingFileBlock },
    { OtaAgentStateCreatingFile,        OtaAgentEventRequestTimer,        initFileHandler,        OtaAgentStateRequestingFileBlock },
    { OtaAgentStateRequestingFileBlock, OtaAgentEventRequestFileBlock,    requestDataHandler,     OtaAgentStateWaitingForFileBlock },
    { OtaAgentStateRequestingFileBlock, OtaAgentEventRequestTimer,        requestDataHandler,     OtaAgentStateWaitingForFileBlock },
    { OtaAgentStateWaitingForFileBlock, OtaAgentEventReceivedFileBlock,   processDataHandler,     OtaAgentStateWaitingForFileBlock },
    { OtaAgentStateWaitingForFileBlock, OtaAgentEventRequestTimer,        requestDataHandler,     OtaAgentStateWaitingForFileBlock },
    { OtaAgentStateWaitingForFileBlock, OtaAgentEventRequestFileBlock,    requestDataHandler,     OtaAgentStateWaitingForFileBlock },
    { OtaAgentStateWaitingForFileBlock, OtaAgentEventRequestJobDocument,  requestJobHandler,      OtaAgentStateWaitingForJob       },
    { OtaAgentStateWaitingForFileBlock, OtaAgentEventReceivedJobDocument, jobNotificationHandler, OtaAgentStateRequestingJob       },
    { OtaAgentStateWaitingForFileBlock, OtaAgentEventCloseFile,           closeFileHandler,       OtaAgentStateWaitingForJob       },
    { OtaAgentStateSuspended,           OtaAgentEventResume,              resumeHandler,          OtaAgentStateRequestingJob       },
    { OtaAgentStateAll,                 OtaAgentEventSuspend,             suspendHandler,         OtaAgentStateSuspended           },
    { OtaAgentStateAll,                 OtaAgentEventUserAbort,           userAbortHandler,       OtaAgentStateWaitingForJob       },
    { OtaAgentStateAll,                 OtaAgentEventShutdown,            shutdownHandler,        OtaAgentStateStopped             },
};

const size_t otaTransitionTableLength = ( sizeof( otaTransitionTable ) / sizeof( otaTransitionTable[ 0 ] ) );

bool findStateTransitionForOtaEvent( OtaState_t currentState,
                                     OtaEvent_t eventId,
                                     OtaEventHandler_t * pActionHandler,
                                     OtaState_t * pNextState)
{
    return findStateTransitionForEvent(
        otaTransitionTable, (uint32_t) otaTransitionTableLength, currentState, eventId, pActionHandler, pNextState);
}