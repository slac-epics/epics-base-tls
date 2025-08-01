/*************************************************************************\
* Copyright (c) 2002 The University of Chicago, as Operator of Argonne
*     National Laboratory.
* Copyright (c) 2002 The Regents of the University of California, as
*     Operator of Los Alamos National Laboratory.
* SPDX-License-Identifier: EPICS
* EPICS BASE is distributed subject to a Software License Agreement found
* in file LICENSE that is included with this distribution.
\*************************************************************************/
newline     "\n"
backslash   "\\"
doublequote "\""
comment     "#"
whitespace  [ \t\r]
escape      {backslash}.
stringchar  [^"\n\\]

name        [a-zA-Z0-9_\-+:.\[\]<>;]
digit       [0-9]
punctuation [(){},]
link        [A-L]

%{
#include "epicsStdlib.h"

static ASINPUTFUNCPTR *my_yyinput;
#undef YY_INPUT
#define YY_INPUT(b,r,ms) (r=(*my_yyinput)((char *)b,ms))

static int yyreset(void)
{
        line_num=1;
        BEGIN INITIAL;
        return(0);
}

%}

%%

UAG     { return(tokenUAG);     }
HAG     { return(tokenHAG);     }
ASG     { return(tokenASG);     }
RULE    { return(tokenRULE);    }
CALC    { return(tokenCALC);    }
METHOD  { return(tokenMETHOD);  }
AUTHORITY { return(tokenAUTHORITY); }
PROTOCOL { return(tokenPROTOCOL);   }

INP{link} {
        yylval.Int64 = (unsigned char)yytext[3];
        yylval.Int64 -= 'A';
        return(tokenINP);
}

[-+]?{digit}*\.{digit}+([eE][-+]?{digit}+)? {
        char *end;
        if (epicsParseDouble((char *)yytext, &yylval.Float64, &end) ) {
            char message[40];
            sprintf(message, "Error parsing Float64: %s", (char *)yytext);
            yyerror(message);
        } else {
            return(tokenFLOAT64);
        }
}

[-+]?{digit}+ { /*integer 64*/
        char *end;
        if (epicsParseInt64((char *)yytext, &yylval.Int64, 10, &end) ) {
            char message[40];
            sprintf(message, "Error parsing Int64: %s", (char *)yytext);
            yyerror(message);
        } else {
            return(tokenINT64);
        }
}

{name}+ { /*unquoted string*/
        yylval.Str=asStrdup(yytext);
        return(tokenSTRING);
}

{doublequote}({stringchar}|{escape})*{doublequote} { /* quoted string */
        yylval.Str=asStrdup(yytext+1);
        yylval.Str[strlen(yylval.Str)-1] = '\0';
        return(tokenSTRING);
}

{doublequote}({stringchar}|{escape})*{newline} { /* bad string */
        yyerror("Newline in quoted string, closing quote missing");
}

{punctuation}   { return(yytext[0]); }

{newline}       { line_num++; }

{comment}.*     ;
{whitespace}    ;

.       {
        char message[40];
        YY_BUFFER_STATE *dummy=0;

        if (isprint((int) yytext[0])) {
            sprintf(message, "Invalid character '%c'", yytext[0]);
        }
        else {
            sprintf(message, "Invalid character 0x%2.2x", yytext[0]);
        }
        yyerror(message);

        /*The following suppress compiler warning messages*/
        if (0) yyunput('c',(unsigned char *) message);
        if (0) yy_switch_to_buffer(*dummy);
}

%%
