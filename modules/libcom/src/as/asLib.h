/* asLib.h */
/*************************************************************************\
* Copyright (c) 2009 UChicago Argonne LLC, as Operator of Argonne
*     National Laboratory.
* Copyright (c) 2002 The Regents of the University of California, as
*     Operator of Los Alamos National Laboratory.
* SPDX-License-Identifier: EPICS
* EPICS BASE is distributed subject to a Software License Agreement found
* in file LICENSE that is included with this distribution.
\*************************************************************************/
/* Author:  Marty Kraimer Date:    09-27-93*/

#ifndef INCasLibh
#define INCasLibh

#include "libComAPI.h"
#include "ellLib.h"
#include "errMdef.h"
#include "errlog.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dbChannel;

/* 0 - Use (unverified) client provided host name string.
 * 1 - Use actual client IP address.  HAG() are resolved to IPs at ACF load time.
 */
LIBCOM_API extern int asCheckClientIP;

typedef struct asIdentity *ASIDENTITYPVT;
typedef struct asIdentity ASIDENTITY;
typedef struct asgMember *ASMEMBERPVT;
typedef struct asgClient *ASCLIENTPVT;
typedef int (*ASINPUTFUNCPTR)(char *buf,int max_size);
typedef enum{
    asClientCOAR        /*Change of access rights*/
    /*For now this is all*/
} asClientStatus;

typedef void (*ASCLIENTCALLBACK) (ASCLIENTPVT,asClientStatus);

/* The following  routines are macros with the following syntax
long asCheckGet(ASCLIENTPVT asClientPvt);
long asCheckPut(ASCLIENTPVT asClientPvt);
*/
#define asCheckGet(asClientPvt) \
    (!asActive || ((asClientPvt)->access >= asREAD))
#define asCheckPut(asClientPvt) \
    (!asActive || ((asClientPvt)->access >= asWRITE))
#define asCheckRPC(asClientPvt) \
    (!asActive || ((asClientPvt)->access >= asRPC))

/* More convenience macros
void *asTrapWriteWithData(ASCLIENTPVT asClientPvt,
     const char *userid, const char *hostid, void *addr,
     int dbrType, int no_elements, void *data);
void asTrapWriteAfter(ASCLIENTPVT asClientPvt);
*/

/* Adapter function for backward compatibility */
LIBCOM_API void * epicsStdCall asTrapWriteWithDataCompat(
    ASCLIENTPVT asClientPvt,
    const char *user, const char *host, struct dbChannel *addr,
    int dbrType, int no_elements, void *data);

#define asTrapWriteWithData(asClientPvt, user, host, addr, type, count, data) \
    ((asActive && (asClientPvt)->trapMask) \
    ? asTrapWriteWithDataCompat((asClientPvt), (user), (host), (addr), (type), (count), (data)) \
    : 0)
#define asTrapWriteAfter(pvt) \
    if (pvt) asTrapWriteAfterWrite(pvt)

/* This macro is for backwards compatibility, upgrade any code
   calling it to use asTrapWriteWithData() instead ASAP:
void *asTrapWriteBefore(ASCLIENTPVT asClientPvt,
     const char *userid, const char *hostid, void *addr);
*/
#define asTrapWriteBefore(asClientPvt, user, host, addr) \
    asTrapWriteWithData(asClientPvt, user, host, addr, 0, 0, NULL)


LIBCOM_API long epicsStdCall asInitialize(ASINPUTFUNCPTR inputfunction);
LIBCOM_API long epicsStdCall asInitFile(
    const char *filename,const char *substitutions);
LIBCOM_API long epicsStdCall asInitFP(FILE *fp,const char *substitutions);
LIBCOM_API long epicsStdCall asInitMem(const char *acf, const char *substitutions);
/*caller must provide permanent storage for asgName*/
LIBCOM_API long epicsStdCall asAddMember(
    ASMEMBERPVT *asMemberPvt,const char *asgName);
LIBCOM_API long epicsStdCall asRemoveMember(ASMEMBERPVT *asMemberPvt);
/*caller must provide permanent storage for newAsgName*/
LIBCOM_API long epicsStdCall asChangeGroup(
    ASMEMBERPVT *asMemberPvt,const char *newAsgName);
LIBCOM_API void * epicsStdCall asGetMemberPvt(ASMEMBERPVT asMemberPvt);
LIBCOM_API void epicsStdCall asPutMemberPvt(
    ASMEMBERPVT asMemberPvt,void *userPvt);
/*client must provide permanent storage for user and host*/
LIBCOM_API long epicsStdCall asAddClient(
    ASCLIENTPVT *asClientPvt,ASMEMBERPVT asMemberPvt,
    int asl,const char *user,char *host);
LIBCOM_API long epicsStdCall asAddClientIdentity(
    ASCLIENTPVT *asClientPvt,ASMEMBERPVT asMemberPvt,
    int asl, ASIDENTITY identity);
/*client must provide permanent storage for user and host*/
LIBCOM_API long epicsStdCall asChangeClient(
    ASCLIENTPVT asClientPvt,int asl,const char *user,char *host);
LIBCOM_API long epicsStdCall asChangeClientIdentity(
    ASCLIENTPVT asClientPvt,int asl, ASIDENTITY identity);
LIBCOM_API long epicsStdCall asRemoveClient(ASCLIENTPVT *asClientPvt);
LIBCOM_API void * epicsStdCall asGetClientPvt(ASCLIENTPVT asClientPvt);
LIBCOM_API void epicsStdCall asPutClientPvt(
    ASCLIENTPVT asClientPvt,void *userPvt);
LIBCOM_API long epicsStdCall asRegisterClientCallback(
    ASCLIENTPVT asClientPvt, ASCLIENTCALLBACK pcallback);
LIBCOM_API long epicsStdCall asComputeAllAsg(void);
/* following declared below after ASG is declared
LIBCOM_API long epicsStdCall asComputeAsg(ASG *pasg);
*/
LIBCOM_API long epicsStdCall asCompute(ASCLIENTPVT asClientPvt);
LIBCOM_API int epicsStdCall asDump(
    void (*memcallback)(ASMEMBERPVT,FILE *),
    void (*clientcallback)(ASCLIENTPVT,FILE *),int verbose);
LIBCOM_API int epicsStdCall asDumpFP(FILE *fp,
    void (*memcallback)(ASMEMBERPVT,FILE *),
    void (*clientcallback)(ASCLIENTPVT,FILE *),int verbose);
LIBCOM_API int epicsStdCall asDumpUag(const char *uagname);
LIBCOM_API int epicsStdCall asDumpUagFP(FILE *fp,const char *uagname);
LIBCOM_API int epicsStdCall asDumpHag(const char *hagname);
LIBCOM_API int epicsStdCall asDumpHagFP(FILE *fp,const char *hagname);
LIBCOM_API int epicsStdCall asDumpRules(const char *asgname);
LIBCOM_API int epicsStdCall asDumpRulesFP(FILE *fp,const char *asgname);
LIBCOM_API int epicsStdCall asDumpMem(const char *asgname,
    void (*memcallback)(ASMEMBERPVT,FILE *),int clients);
LIBCOM_API int epicsStdCall asDumpMemFP(FILE *fp,const char *asgname,
    void (*memcallback)(ASMEMBERPVT,FILE *),int clients);
LIBCOM_API int epicsStdCall asDumpHash(void);
LIBCOM_API int epicsStdCall asDumpHashFP(FILE *fp);

LIBCOM_API void * epicsStdCall asTrapWriteBeforeWithData(
    const char *userid, const char *hostid, struct dbChannel *addr,
    int dbrType, int no_elements, void *data);
LIBCOM_API void * epicsStdCall asTrapWriteBeforeWithIdentityData(
    ASIDENTITY identity, struct dbChannel *addr,
    int dbrType, int no_elements, void *data);

LIBCOM_API void epicsStdCall asTrapWriteAfterWrite(void *pvt);

#define S_asLib_clientsExist    (M_asLib| 1) /*Client Exists*/
#define S_asLib_noUag           (M_asLib| 2) /*User Access Group does not exist*/
#define S_asLib_noHag           (M_asLib| 3) /*Host Access Group does not exist*/
#define S_asLib_noAccess        (M_asLib| 4) /*access security: no access allowed*/
#define S_asLib_noModify        (M_asLib| 5) /*access security: no modification allowed*/
#define S_asLib_badConfig       (M_asLib| 6) /*access security: bad configuration file*/
#define S_asLib_badCalc         (M_asLib| 7) /*access security: bad calculation espression*/
#define S_asLib_dupAsg          (M_asLib| 8) /*Duplicate Access Security Group */
#define S_asLib_InitFailed      (M_asLib| 9) /*access security: Init failed*/
#define S_asLib_asNotActive     (M_asLib|10) /*access security is not active*/
#define S_asLib_badMember       (M_asLib|11) /*access security: bad ASMEMBERPVT*/
#define S_asLib_badClient       (M_asLib|12) /*access security: bad ASCLIENTPVT*/
#define S_asLib_badAsg          (M_asLib|13) /*access security: bad ASG*/
#define S_asLib_noMemory        (M_asLib|14) /*access security: no Memory */
#define S_asLib_dupMethod       (M_asLib|15) /* Duplicate method name in rule */
#define S_asLib_dupAuthority    (M_asLib|16) /* Duplicate authority name in rule */

/*Private declarations */
LIBCOM_API extern int asActive;

/* definition of access rights*/
typedef enum{asNOACCESS,asREAD,asWRITE,asRPC} asAccessRights;

struct gphPvt;

/*Base pointers for access security*/
typedef struct asBase{
    ELLLIST         uagList;
    ELLLIST         hagList;
    ELLLIST         authList;
    ELLLIST         asgList;
    struct gphPvt   *phash;
} ASBASE;

LIBCOM_API extern volatile ASBASE *pasbase;

/*Defs for User Access Groups*/
typedef struct{
    ELLNODE         node;
    char            *user;
} UAGNAME;
typedef struct uag{
    ELLNODE         node;
    char            *name;
    ELLLIST         list;   /*list of UAGNAME*/
} UAG;
/*Defs for Host Access Groups*/
typedef struct{
    ELLNODE         node;
    char            host[1];
} HAGNAME;
typedef struct hag{
    ELLNODE         node;
    char            *name;
    ELLLIST         list;   /*list of HAGNAME*/
} HAG;
// Defs for Authority Chains
typedef struct authchain {
    ELLNODE         node;
    char *          name;       /* Authority chain ID */
    char *          chain;      /* Authority Chain: Common Name or newline-separated Chain of Common Names (root to issuer) */
    ELLLIST         list;       /* List of named Authority definitions (pointer to this list) */
} AUTHCHAIN;
/*Defs for Access SecurityGroups*/
typedef struct {
    ELLNODE         node;
    UAG             *puag;
}ASGUAG;
typedef struct {
    ELLNODE         node;
    HAG             *phag;
}ASGHAG;
typedef struct {
    ELLNODE         node;
    struct method   *pmethod;
} ASGMETHOD;
typedef struct {
    ELLNODE         node;
    struct authority *pauthority;
} ASGAUTHORITY;

#define AS_TRAP_WRITE 1

enum AsProtocol {
    AS_PROTOCOL_NOT_SET = -1,
    AS_PROTOCOL_TCP = 0,
    AS_PROTOCOL_TLS = 1
};

typedef struct{
    ELLNODE         node;
    asAccessRights  access;
    int             level;
    unsigned long   inpUsed; /*bitmap of which inputs are used*/
    int             result;  /*Result of calc converted to TRUE/FALSE*/
    char            *calc;
    void            *rpcl;
    ELLLIST         uagList; /*List of ASGUAG*/
    ELLLIST         hagList; /*List of ASGHAG*/
    int             trapMask;
    int             ignore; // 1 if rule to be ignored because of unknown elements
    enum AsProtocol protocol; /* -1: ignore, AS_PROTOCOL_TCP: not TLS, AS_PROTOCOL_TLS: TLS */
    ELLLIST         methodList; /*List of ASGMETHOD*/
    ELLLIST         authList; /*List of ASGAUTHORITY*/
} ASGRULE;
typedef struct{
    ELLNODE         node;
    char            *inp;
    void            *capvt;
    struct asg      *pasg;
    int             inpIndex;
}ASGINP;

typedef struct asg{
    ELLNODE         node;
    char            *name;
    ELLLIST         inpList;
    ELLLIST         ruleList;
    ELLLIST         memberList;
    double          *pavalue;   /*pointer to array of input values*/
    unsigned long   inpBad;     /*bitmap of which inputs are bad*/
    unsigned long   inpChanged; /*bitmap of inputs that changed*/
} ASG;
typedef struct asgMember {
    ELLNODE         node;
    ASG             *pasg;
    ELLLIST         clientList;
    const char      *asgName;
    void            *userPvt;
} ASGMEMBER;

typedef struct asIdentity {
    const char *user;
    char *host;
    const char *method;
    const char *authority;
    enum AsProtocol protocol;
} ASGIDENTITY;

typedef struct asgClient {
    ELLNODE         node;
    ASGMEMBER       *pasgMember;
    ASIDENTITY      identity;
    void            *userPvt;
    ASCLIENTCALLBACK pcallback;
    int             level;
    asAccessRights  access;
    int             trapMask;
} ASGCLIENT;

/* Define METHOD and AUTHORITY structures here for use in ASGRULE */
typedef struct method{
    char            *name;
} METHOD;

typedef struct authority{
    char            *name;
} AUTHORITY;

LIBCOM_API long epicsStdCall asComputeAsg(ASG *pasg);
/*following is "friend" function*/
LIBCOM_API void * epicsStdCall asCalloc(size_t nobj,size_t size);
LIBCOM_API char * epicsStdCall asStrdup(unsigned char *str);
LIBCOM_API void asFreeAll(ASBASE *pasbase);

// The maximum length of the Authority string that can be processed
// by the EPICS Authorization system.  Set as large as you like to handle the longest string you think will be provided.
// Holds the concatenated common names of the chain of authority all the way back to the root certificate.
#define MAX_AUTH_CHAIN_STRING 2048
#ifdef __cplusplus
}
#endif

#endif /*INCasLibh*/
