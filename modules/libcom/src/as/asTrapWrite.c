/*************************************************************************\
* Copyright (c) 2002 The University of Chicago, as Operator of Argonne
*     National Laboratory.
* Copyright (c) 2002 The Regents of the University of California, as
*     Operator of Los Alamos National Laboratory.
* SPDX-License-Identifier: EPICS
* EPICS BASE is distributed subject to a Software License Agreement found
* in file LICENSE that is included with this distribution.
\*************************************************************************/
/*asTrapWrite.c */
/* Author:  Marty Kraimer Date:    07NOV2000 */

/* Matthias Clausen and Vladis Korobov at DESY
 * implemented the first logging of Channel Access Puts
 * This implementation uses many ideas from their implementation
*/

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "ellLib.h"
#include "freeList.h"
#include "cantProceed.h"
#include "epicsMutex.h"
#include "ellLib.h"
#include <dbChannel.h>

#include "asLib.h"
#include "asTrapWrite.h"

typedef struct listenerPvt {
    ELLNODE node;
    struct listener *plistener;
    void *userPvt;
}listenerPvt;

typedef struct listener{
    ELLNODE node;
    asTrapWriteListener func;
}listener;

typedef struct writeMessage {
    ELLNODE node;
    asTrapWriteMessage message;
    ELLLIST listenerPvtList;
}writeMessage;


typedef struct asTrapWritePvt
{
    ELLLIST listenerList;
    ELLLIST writeMessageList;
    void *freeListWriteMessage;
    void *freeListListenerPvt;
    epicsMutexId lock;
}asTrapWritePvt;

static asTrapWritePvt *pasTrapWritePvt = 0;

static void asTrapWriteInit(void)
{
    pasTrapWritePvt = callocMustSucceed(1,sizeof(asTrapWritePvt),"asTrapWriteInit");
    ellInit(&pasTrapWritePvt->listenerList);
    ellInit(&pasTrapWritePvt->writeMessageList);
    freeListInitPvt(
        &pasTrapWritePvt->freeListWriteMessage,sizeof(writeMessage),20);
    freeListInitPvt(
        &pasTrapWritePvt->freeListListenerPvt,sizeof(listenerPvt),20);
    pasTrapWritePvt->lock = epicsMutexMustCreate();
}

asTrapWriteId epicsStdCall asTrapWriteRegisterListener(
    asTrapWriteListener func)
{
    listener *plistener;
    if(pasTrapWritePvt==0) asTrapWriteInit();
    plistener = callocMustSucceed(1,sizeof(listener),"asTrapWriteRegisterListener");
    plistener->func = func;
    epicsMutexMustLock(pasTrapWritePvt->lock);
    ellAdd(&pasTrapWritePvt->listenerList,&plistener->node);
    epicsMutexUnlock(pasTrapWritePvt->lock);
    return((asTrapWriteId)plistener);
}

void epicsStdCall asTrapWriteUnregisterListener(asTrapWriteId id)
{
    listener *plistener = (listener *)id;
    writeMessage *pwriteMessage;

    if(pasTrapWritePvt==0) return;
    epicsMutexMustLock(pasTrapWritePvt->lock);
    pwriteMessage = (writeMessage *)ellFirst(&pasTrapWritePvt->writeMessageList);
    while(pwriteMessage) {
        listenerPvt *plistenerPvt
             = (listenerPvt *)ellFirst(&pwriteMessage->listenerPvtList);
        while(plistenerPvt) {
            listenerPvt *pnext
                 = (listenerPvt *)ellNext(&plistenerPvt->node);
            if(plistenerPvt->plistener == plistener) {
                ellDelete(&pwriteMessage->listenerPvtList,&plistenerPvt->node);
                freeListFree(pasTrapWritePvt->freeListListenerPvt, plistenerPvt);
            }
            plistenerPvt = pnext;
        }
        pwriteMessage = (writeMessage *)ellNext(&pwriteMessage->node);
    }
    ellDelete(&pasTrapWritePvt->listenerList,&plistener->node);
    free(plistener);
    epicsMutexUnlock(pasTrapWritePvt->lock);
}

void * epicsStdCall asTrapWriteBeforeWithData(
    const char *userid, const char *hostid, dbChannel *chan,
    int dbrType, int no_elements, void *data)
{
    return asTrapWriteBeforeWithIdentityData((ASIDENTITY){ .user = userid, .host = (char *)hostid, .method = "ca"  }, chan, dbrType, no_elements, data);
}

void * epicsStdCall asTrapWriteBeforeWithIdentityData(
    ASIDENTITY identity, dbChannel *chan,
    int dbrType, int no_elements, void *data)
{
    writeMessage *pwriteMessage;
    listener *plistener;
    void *pfieldsave;

    if (pasTrapWritePvt == 0 ||
        ellCount(&pasTrapWritePvt->listenerList) <= 0) return 0;

    pwriteMessage = (writeMessage *)freeListCalloc(
        pasTrapWritePvt->freeListWriteMessage);
    pwriteMessage->message.userid = identity.user;
    pwriteMessage->message.hostid = identity.host;
    pwriteMessage->message.method = identity.method;
    pwriteMessage->message.authority = identity.authority;
    pwriteMessage->message.protocol = identity.protocol;
    pwriteMessage->message.serverSpecific = chan;
    pwriteMessage->message.dbrType = dbrType;
    pwriteMessage->message.no_elements = no_elements;
    pwriteMessage->message.data = data;
    ellInit(&pwriteMessage->listenerPvtList);

    epicsMutexMustLock(pasTrapWritePvt->lock);
    pfieldsave = chan->addr.pfield;
    ellAdd(&pasTrapWritePvt->writeMessageList, &pwriteMessage->node);
    plistener = (listener *)ellFirst(&pasTrapWritePvt->listenerList);
    while (plistener) {
        listenerPvt *plistenerPvt = (listenerPvt *)freeListCalloc(
            pasTrapWritePvt->freeListListenerPvt);

        plistenerPvt->plistener = plistener;
        pwriteMessage->message.userPvt = 0;
        plistener->func(&pwriteMessage->message, 0);
        chan->addr.pfield = pfieldsave;
        plistenerPvt->userPvt = pwriteMessage->message.userPvt;
        ellAdd(&pwriteMessage->listenerPvtList, &plistenerPvt->node);
        plistener = (listener *)ellNext(&plistener->node);
    }
    epicsMutexUnlock(pasTrapWritePvt->lock);
    return pwriteMessage;
}

void * epicsStdCall asTrapWriteWithDataCompat(
    ASCLIENTPVT asClientPvt, const char *user, const char *host, dbChannel *addr,
    int dbrType, int no_elements, void *data)
{
    return asTrapWriteBeforeWithIdentityData(
        (ASIDENTITY){
            .user = user,
            .host = (char *)host,
            .method = asClientPvt->identity.method,
            .authority = asClientPvt->identity.authority,
            .protocol = asClientPvt->identity.protocol
        },
        addr, dbrType, no_elements, data);
}

void epicsStdCall asTrapWriteAfterWrite(void *pvt)
{
    writeMessage *pwriteMessage = (writeMessage *)pvt;
    listenerPvt *plistenerPvt;
    dbChannel *chan;
    void *pfieldsave;

    if (pwriteMessage == 0 ||
        pasTrapWritePvt == 0) return;

    epicsMutexMustLock(pasTrapWritePvt->lock);
    chan = pwriteMessage->message.serverSpecific;
    pfieldsave = chan->addr.pfield;
    plistenerPvt = (listenerPvt *)ellFirst(&pwriteMessage->listenerPvtList);
    while (plistenerPvt) {
        listenerPvt *pnext = (listenerPvt *)ellNext(&plistenerPvt->node);
        listener *plistener = plistenerPvt->plistener;

        pwriteMessage->message.userPvt = plistenerPvt->userPvt;
        plistener->func(&pwriteMessage->message, 1);
        chan->addr.pfield = pfieldsave;
        ellDelete(&pwriteMessage->listenerPvtList, &plistenerPvt->node);
        freeListFree(pasTrapWritePvt->freeListListenerPvt, plistenerPvt);
        plistenerPvt = pnext;
    }
    ellDelete(&pasTrapWritePvt->writeMessageList, &pwriteMessage->node);
    freeListFree(pasTrapWritePvt->freeListWriteMessage, pwriteMessage);
    epicsMutexUnlock(pasTrapWritePvt->lock);
}
