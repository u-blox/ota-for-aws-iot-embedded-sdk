#include "ota_state_machine_private.h"


bool findStateTransitionForEvent( OtaStateTableEntry_t * pTransitionTable,
                                  uint32_t tableCount,
                                  OtaState_t currentState,
                                  OtaEvent_t eventId,
                                  OtaEventHandler_t * pActionHandler,
                                  OtaState_t * pNextState)
{
    bool found = false;
    uint32_t i;
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

