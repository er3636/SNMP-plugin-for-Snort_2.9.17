/**
 ******************************************************************
 Copyright 1989, 1991, 1992 by Carnegie Mellon University

 All Rights Reserved

 Permission to use, copy, modify, and distribute this software and its
 documentation for any purpose and without fee is hereby granted,
 provided that the above copyright notice appear in all copies and that
 both that copyright notice and this permission notice appear in
 supporting documentation, and that the name of CMU not be
 used in advertising or publicity pertaining to distribution of the
 software without specific, written prior permission.
 
 CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 SOFTWARE.
 ******************************************************************/

/*******************************************************************
 *      Project            : Snort       		            *
 *      Module file name   : SnmpTrap 			            *
 *      Objective          : Generate an SNMP {trap|Inform} for     *
 *                           every alert                            * 
 *      Related Headers    : spo_SnmpTrap.h			    *
 *      Start Date 	   : 07-07-2001			            *
 *      Related Info       : man snort   		            *
 *                           man snmpcmd                            *
 *      Requirements       : ucd-snmp 4.2.1 library and headers     * 
 *      Authors		   : Glenn Mansfield Keeni                  *
 *			     Cyber Solutions Inc.                   *
 *                           Sendai, Japan                          *
 *            		   : K. Jayanthi                            *
 *			     Intelligent Software Solutions         *
 *                           Bangalore, India                       *
 *                                                                  *
 *      Acknowledgments    : The NetSnmp code has been liberally    *
 *                           used.                                  * 
 *                           [url:http://net-snmp.sourceforge.net/  *
 *                           The Snort-Snmp development started as  *
 *                           Part of the IDWS project of the        *    
 *                           Information Promotion Agency, Japan    *    
 *                           http://www.cysol.co.jp/research/ipasec/
 *	Modified on          Comments				    *
 *	2012/10/26           Adopted to Snort 2.9.3.1
 *	-----------          --------				    *
 ********************************************************************
 */
#ifdef ENABLE_SNMP

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "util.h"
#include "event.h"
#include "decode.h"
#include "rules.h"
#include "plugbase.h"
#include "snort_debug.h"
#include "generators.h"

#include "snort.h"
#include "build.h"

extern SnortConfig *snort_conf_for_parsing;

/* Internal functions */
static void SnmpTrapInit(struct _SnortConfig *, char *);
static void SnmpTrapCleanExitFunc(int, void *);
#ifdef SNORT_RELOAD
static void SnmpTrapRestartFunc(int, void *);
#endif
static void SpoSnmpTrap(Packet *, char *, void *, Event *event);
#ifdef  HAVE_NETSNMP
int snort_snmp_parse_args();
#endif

extern OptTreeNode *otn_tmp; /* global ptr to current rule data */

/*
 *    SNMP Headers 
 *    You will need to have ucd-snmp (ucd-snmp-4.2.1 or above), or
 *    net-snmp (net-snmp-5.0.3 or above), installed 
 */
#ifdef HAVE_NETSNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/version.h>
#include <net-snmp/library/snmp_parse_args.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/snmpv3.h>
#include <net-snmp/library/keytools.h>
#else
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#include <ucd-snmp/snmp_parse_args.h>
#include <ucd-snmp/system.h>
#include <ucd-snmp/version.h>
#include <ucd-snmp/snmpv3.h>
#include <ucd-snmp/keytools.h>
#endif

#include <netdb.h>
#include <strings.h>
#include <sys/resource.h>

/*
 *******************
 *
 * packetPrinting.c
 *
 *******************
 */

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif

#define DEBUG                0
#define IP_HEADER_LENGTH    20
#define TCP_PROTOCOL_LENGTH 20
#define UDP_PROTOCOL_LENGTH 8

#ifdef  INET6
#define IP6_HEADER_LENGTH   40
#endif

#define USE_MD5             0x01
#define USE_RIPEMD          0x02
#define USE_SHA1            0x03

#define MD5NAME             "MD5"
#define RIPEMDNAME          "RIPEMD"
#define SHA1NAME            "SHA1"

#define HASHLEN_MD5           16
#define HASHLEN_RIPEMD        20
#define HASHLEN_SHA1          20

#define TTLPOS                 8
#define CHECKSUMPOS           10
#define CHECKSUMLEN            2

#define MAXBUF              1024

#define SNORT_DEFAULTSNMPTRAPD_PORT 162
#define MAXALERTSINONESEC           10

/* 
 *
 * The MOs that are there in the Sensor MIB and the corresponding OIDs 
 * Should be automatically extracted at some stage - done manually now 
 * Refer to SnortAlertMIB.txt  
 *
 */

#define   _OID_sidaAlertGenericOID       ".1.3.6.1.4.1.10234.2.1.3.3"
#define   _OID_sidaAlertScanStatus       ".1.3.6.1.4.1.10234.2.1.3.4"
#define   _OID_sidaSensorID              ".1.3.6.1.4.1.10234.2.1.1.1.1"
#define   _OID_sidaSensorDescription     ".1.3.6.1.4.1.10234.2.1.1.1.2"
#define   _OID_sidaSensorVersion         ".1.3.6.1.4.1.10234.2.1.1.1.3"
#define   _OID_sidaSensorLocation        ".1.3.6.1.4.1.10234.2.1.1.1.4"
#define   _OID_sidaSensorAddressType     ".1.3.6.1.4.1.10234.2.1.1.1.5"
#define   _OID_sidaSensorAddress         ".1.3.6.1.4.1.10234.2.1.1.1.6"
#define   _OID_sidaSensorInterfaceIndex  ".1.3.6.1.4.1.10234.2.1.1.1.7"
#define   _OID_sidaSensorManufacturer    ".1.3.6.1.4.1.10234.2.1.1.1.8"
#define   _OID_sidaSensorProductName     ".1.3.6.1.4.1.10234.2.1.1.1.9"
#define   _OID_sidaSensorProductID       ".1.3.6.1.4.1.10234.2.1.1.1.10"
#define   _OID_sidaAlertID               ".1.3.6.1.4.1.10234.2.1.2.1.1" 
#define   _OID_sidaAlertTimeStamp        ".1.3.6.1.4.1.10234.2.1.2.1.2"
#define   _OID_sidaAlertActionsTaken     ".1.3.6.1.4.1.10234.2.1.2.1.3"
#define   _OID_sidaAlertMsg              ".1.3.6.1.4.1.10234.2.1.2.1.4"
#define   _OID_sidaAlertMoreInfo         ".1.3.6.1.4.1.10234.2.1.2.1.5"
#define   _OID_sidaAlertSrcAddressType   ".1.3.6.1.4.1.10234.2.1.2.1.6"
#define   _OID_sidaAlertSrcAddress       ".1.3.6.1.4.1.10234.2.1.2.1.7"
#define   _OID_sidaAlertDstAddressType   ".1.3.6.1.4.1.10234.2.1.2.1.8"
#define   _OID_sidaAlertDstAddress       ".1.3.6.1.4.1.10234.2.1.2.1.9"
#define   _OID_sidaAlertSrcPort          ".1.3.6.1.4.1.10234.2.1.2.1.10"
#define   _OID_sidaAlertDstPort          ".1.3.6.1.4.1.10234.2.1.2.1.11"
#define   _OID_sidaAlertStartTime        ".1.3.6.1.4.1.10234.2.1.2.1.12"
#define   _OID_sidaAlertOccurrences      ".1.3.6.1.4.1.10234.2.1.2.1.13"
#define   _OID_sidaAlertImpact           ".1.3.6.1.4.1.10234.2.1.2.1.14"
#define   _OID_sidaAlertSrcAddressList   ".1.3.6.1.4.1.10234.2.1.2.1.15"
#define   _OID_sidaAlertDstAddressList   ".1.3.6.1.4.1.10234.2.1.2.1.16"
#define   _OID_sidaAlertSrcPortList      ".1.3.6.1.4.1.10234.2.1.2.1.17"
#define   _OID_sidaAlertDstPortList      ".1.3.6.1.4.1.10234.2.1.2.1.18"
#define   _OID_sidaAlertScanDuration     ".1.3.6.1.4.1.10234.2.1.2.1.19"
#define   _OID_sidaAlertScannedHosts     ".1.3.6.1.4.1.10234.2.1.2.1.20"
#define   _OID_sidaAlertTCPScanCount     ".1.3.6.1.4.1.10234.2.1.2.1.21"
#define   _OID_sidaAlertUDPScanCount     ".1.3.6.1.4.1.10234.2.1.2.1.22"
#define   _OID_sidaAlertScanType         ".1.3.6.1.4.1.10234.2.1.2.1.23"
#define   _OID_sidaAlertEventStatus      ".1.3.6.1.4.1.10234.2.1.2.1.24"
#define   _OID_sidaAlertEventPriority    ".1.3.6.1.4.1.10234.2.1.2.1.25"
#define   _OID_sidaAlertSrcMacAddress    ".1.3.6.1.4.1.10234.2.1.2.1.26"
#define   _OID_sidaAlertDstMacAddress    ".1.3.6.1.4.1.10234.2.1.2.1.27"
#define   _OID_sidaAlertProto            ".1.3.6.1.4.1.10234.2.1.2.1.28"
#define   _OID_sidaAlertRuleID           ".1.3.6.1.4.1.10234.2.1.2.1.29"
#define   _OID_sidaAlertRuleRevision     ".1.3.6.1.4.1.10234.2.1.2.1.30"
#define   _OID_sidaAlertPacketPrint      ".1.3.6.1.4.1.10234.2.1.2.1.31"
#define   _OID_EngineID                  ".1.3.6.1.6.3.10.2.1.1.0"

#define   I_TYPE "i"
#define   S_TYPE "s"
#define   X_TYPE "x"
#define   C_TYPE "c"
#define   G_TYPE "u"
#define   U_TYPE "u"
#define   B_TYPE "b"

char
		*SnmpTrapMOs[36][2] = { { _OID_sidaSensorID, I_TYPE }, {
				_OID_sidaSensorVersion, S_TYPE }, { _OID_sidaSensorAddressType,
				I_TYPE }, { _OID_sidaSensorAddress, S_TYPE }, {
				_OID_sidaAlertID, I_TYPE },
				{ _OID_sidaAlertTimeStamp, S_TYPE }, {
						_OID_sidaAlertActionsTaken, B_TYPE }, {
						_OID_sidaAlertMsg, S_TYPE }, { _OID_sidaAlertMoreInfo,
						S_TYPE }, { _OID_sidaAlertSrcAddressType, I_TYPE }, {
						_OID_sidaAlertSrcAddress, S_TYPE }, {
						_OID_sidaAlertDstAddressType, I_TYPE }, {
						_OID_sidaAlertDstAddress, S_TYPE }, {
						_OID_sidaAlertSrcPort, I_TYPE }, {
						_OID_sidaAlertDstPort, I_TYPE }, {
						_OID_sidaAlertStartTime, S_TYPE }, {
						_OID_sidaAlertOccurrences, I_TYPE }, {
						_OID_sidaAlertImpact, I_TYPE }, {
						_OID_sidaAlertSrcAddressList, S_TYPE }, {
						_OID_sidaAlertDstAddressList, S_TYPE }, {
						_OID_sidaAlertSrcPortList, S_TYPE }, {
						_OID_sidaAlertDstPortList, S_TYPE }, {
						_OID_sidaAlertScanDuration, C_TYPE }, {
						_OID_sidaAlertScannedHosts, C_TYPE }, {
						_OID_sidaAlertTCPScanCount, C_TYPE }, {
						_OID_sidaAlertUDPScanCount, C_TYPE }, {
						_OID_sidaAlertScanType, I_TYPE }, {
						_OID_sidaAlertEventStatus, I_TYPE }, {
						_OID_sidaAlertEventPriority, I_TYPE }, {
						_OID_sidaAlertSrcMacAddress, X_TYPE }, {
						_OID_sidaAlertDstMacAddress, X_TYPE }, {
						_OID_sidaAlertProto, S_TYPE }, { _OID_sidaAlertRuleID,
						I_TYPE }, { _OID_sidaAlertRuleRevision, I_TYPE }, {
						_OID_sidaAlertPacketPrint, S_TYPE }, { _OID_EngineID,
						X_TYPE } };

enum {
	SENSORID = 0,
	SENSORVERSION = 1,
	SENSORADDRESSTYPE = 2,
	SENSORADDRESS = 3,
	ALERTID = 4,
	ALERTTIMESTAMP = 5,
	ALERTACTIONSTAKEN = 6,
	ALERTMSG = 7,
	ALERTMOREINFO = 8,
	ALERTSRCADDRESSTYPE = 9,
	ALERTSRCADDRESS = 10,
	ALERTDSTADDRESSTYPE = 11,
	ALERTDSTADDRESS = 12,
	ALERTSRCPORT = 13,
	ALERTDSTPORT = 14,
	ALERTSTARTTIME = 15,
	ALERTOCCURRENCES = 16,
	ALERTIMPACT = 17,
	ALERTSRCADDRESSLST = 18,
	ALERTDSTADDRESSLST = 19,
	ALERTSRCPORTLST = 20,
	ALERTDSTPORTLST = 21,
	ALERTSCANDURATION = 22,
	ALERTSCANNEDHOSTS = 23,
	ALERTTCPSCANCOUNT = 24,
	ALERTUDPSCANCOUNT = 25,
	ALERTSCANTYPE = 26,
	ALERTEVENTSTATUS = 27,
	ALERTEVENTPRIORITY = 28,
	ALERTSRCMACADDRESS = 29,
	ALERTDSTMACADDRESS = 30,
	ALERTPROTO = 31,
	ALERTRULEID = 32,
	ALERTRULEREVISION = 33,
	ALERTPACKETPRINT = 34,
	ENGINEID = 35
};
enum {
	OID_INDEX = 0, TYPE_INDEX = 1
};

struct AlertData {
	char *alertID;
	char *alertImpact;
	char *alertVersion;
	char *timeOffset;
	char *timeNtpStamp;
	char *timeDate;
	char *timeTime;
	char *detectOffset;
	char *detectNtpStamp;
	char *detectDate;
	char *detectTime;
	char *sourceIndex;
	int sourceAddressType;
	char *sourceID;
	char *sourceSpoofed;
	char *targetIndex;
	int targetAddressType;
	char *targetID;
	char *targetDecoy;
	char *toolAlertName;
	char *toolAlertCommand;
	char *additionalDataMeaning;
	char *additionalDataType;
	char *additionalDataValue;
	struct AlertData * next;
};

#define NOOFCLASSIFICATIONS 12

char *Classifications[] = { "unknown", "bad-unknown", "not-suspicious",
		"attempted-admin", "successful-admin", "attempted-dos",
		"successful-dos", "attempted-recon", "successful-recon-limited",
		"successful-recon-largescale", "attempted-user", "successful-user" };

/*
 * Related  Snmp parameters are held in this structure.
 * Most of the data Version, Manager, community, port are
 * stored in session sub-structure.
 */
typedef struct SnmpTrapData {
	char * engineID;
	char * facility;
	int trapOrInform;
	int trapdPort;
	int sensorID;
	char * sensorVersion;
	int addrLen;
	int compact;
	int pPrint;
	int hashAlgorithm;
	int hashLength;
	struct sockaddr_in trapdInfo;
	struct snmp_session session;
} SnmpTrapData;

/*
 * Includes from other sources:  spp_portscan.c 
 */
#if 0
/* Definitions for scan types */
struct spp_timeval
{
	time_t tv_sec;
	time_t tv_usec;
};

typedef enum _scanType
{
	sNONE = 0, sUDP = 1, sSYN = 2, sSYNFIN = 4, sFIN = 8, sNULL = 16,
	sXMAS = 32, sFULLXMAS = 64, sRESERVEDBITS = 128, sVECNA = 256, sNOACK = 512,
	sNMAPID = 1024,
	sSPAU = 2048, sINVALIDACK = 4096
}ScanType;

/* Structures for keeping track of connection information. */
typedef struct _connectionInfo
{
	ScanType scanType;
	u_short sport;
	u_short dport;
	struct spp_timeval timestamp;
	char tcpFlags[9]; /* Eight flags and a NULL */
	u_char *packetData;
	struct _connectionInfo *prevNode;
	struct _connectionInfo *nextNode;
}ConnectionInfo;

typedef struct _destinationInfo
{
	struct in_addr daddr;
	int numberOfConnections;
	ConnectionInfo *connectionsList;
	struct _destinationInfo *prevNode;
	struct _destinationInfo *nextNode;
}DestinationInfo;

typedef struct _sourceInfo
{
	struct in_addr saddr;
	int numberOfConnections;
	int numberOfDestinations;
	int numberOfTCPConnections;
	int numberOfUDPConnections;
	int totalNumberOfTCPConnections;
	int totalNumberOfUDPConnections;
	int totalNumberOfDestinations;

	struct spp_timeval firstPacketTime;
	struct spp_timeval lastPacketTime;
	int reportStealth;

	int stealthScanUsed;
	int scanDetected;
	struct spp_timeval reportTime; /* last time we reported on this
	 * source's activities */
	DestinationInfo *destinationsList;
	u_int32_t event_id;
	struct _sourceInfo *prevNode;
	struct _sourceInfo *nextNode;
}SourceInfo;

typedef struct _scanList
{
	SourceInfo *listHead;
	SourceInfo *lastSource;
	long numberOfSources; /* must be as large as address space */
}ScanList;

/*******            End of copied includes              ********/
#endif

int CountSnmpArgs();
int snmp_input();
void startIDWS(Packet *, char *, Event *);
void InitSnmpSession();
void GetSensorVersion(SnmpTrapData *);
void sendSNMPInform(Packet *, char *, long, SnmpTrapData *, Event *);
int sendInform(Packet *, char *, long, SnmpTrapData *, Event *);
int ParseOidAndAddToPdu(int, long, long, char *, struct snmp_pdu *);
int ParseSensorOidAndAddToPdu(int, long, char *, struct snmp_pdu *);
int getImpactCode(char *);
void getScanDetails(Packet *, char *msg, Event *event, char **scanSource,
		long *scanDuration, int *scannedHosts, int *TCPScanCount,
		int *UDPScanCount, int *scanType, int *scanStatus);
SnmpTrapData *ParseSnmpTrapArgs();

void make_hash_value(const int, u_char *, unsigned long, u_char *);
void ip_print_hashing(const struct pcap_pkthdr32 *ch, u_char *cp, char *buf,
		SnmpTrapData * SnmpData);

#ifdef INET6
void
ipv6_print_hashing(const struct pcap_pkthdr32 *ch, u_char *cp, char *buf,
		SnmpTrapData * SnmpData);
#endif /* INET6 */

/*
 * I need to have some way to know my address
 */
static char *sensorAddress = NULL;
static int sensorAddressType = 0;
static long alertID = 1;
static int maxAlertsInOneSec = MAXALERTSINONESEC;

static SnmpTrapData SnmpData;

static size_t hash_length;
static int hash_func;

// Is in spp_sfportscan.c
extern Packet *g_tmp_pkt;

void SnmpTrapUsage();
/*
 * Function: SetupSnmpTrap()
 * Function: SnmpTrapSetup()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */

/*void SetupSnmpTrap() */
void SnmpTrapSetup() {
	/* link the preprocessor keyword to the init function in
	 the preproc list */
	RegisterOutputPlugin("trap_snmp", OUTPUT_TYPE_FLAG__ALERT, SnmpTrapInit);
	DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: SnmpTrap is setup...\n"););
}

/*
 * Function: SnmpTrapInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void SnmpTrapInit(struct _SnortConfig *sc, char *args) {
	DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: SnmpTrap Initialized\n"););

	/* parse the argument list from the rules file */
	ParseSnmpTrapArgs(args, &SnmpData);

	GetSensorVersion(&SnmpData);
	//    pv.alert_plugin_active = 1;
	// snort_conf_for_parsing->no_alert = 0;

	/* Do the Session initialization part too */
	InitSnmpSession(&SnmpData);

	/* Get the Sensor Address */
	// Stop this. Obtain sensorAddress from -s "..." in snort.conf
	//sensorAddress = GetIP(snort_conf_for_parsing->interface);
	sensorAddressType = 1; /* There should be some way to know this !! */
	DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking SnmpTrap functions to call lists...\n"););
	/* Set the preprocessor function into the function list */
	AddFuncToOutputList(sc, SpoSnmpTrap, OUTPUT_TYPE_FLAG__ALERT, &SnmpData);
	AddFuncToCleanExitList(SnmpTrapCleanExitFunc, &SnmpData);
#ifdef SNORT_RELOAD
	AddFuncToReloadList(SnmpTrapRestartFunc, &SnmpData);
#endif
}

/*
 **********
 * 
 *  Get the Snort version
 *
 **********
 */
void GetSensorVersion(SnmpTrapData *SnmpData) {
	char VersionBuf[256];
	char *VersionPtr;
	snprintf(VersionBuf, sizeof(VersionBuf),
			"Snort! <*-\nVersion %s (Build %s)", VERSION, BUILD);
	VersionPtr = malloc(strlen(VersionBuf) + 1);
	if (!VersionPtr) {
		ErrorMessage("GetSnortVersion: Malloc failed \n");
		FatalError("Quitting in GetSnortVersion\n");
	}
	strncpy(VersionPtr, VersionBuf, strlen(VersionBuf) + 1);
	SnmpData->sensorVersion = VersionPtr;
}

/*
 * Function: ParseSnmpTrapArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */

SnmpTrapData *ParseSnmpTrapArgs(char *args, SnmpTrapData *data) {
	char *facility;
	char *nArgs;
	char *Argv[128];
	int sensorID;
	char *sensorPtr;
	int argc;
	int nargc;
	struct hostent *tInfo;
	char *lastColon;
	char *cPtr;
	char *tPtr;
#ifndef HAVE_NETSNMP
	int tmpPort;
#endif
	tInfo = (struct hostent *) NULL;
	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Args: %s\n", args););

	if (args == NULL) {
		ErrorMessage("SnmpTrapPlugin:  parameters are required !! \n");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin");
	}

	facility = args;

	nArgs = index(args, ',');
	if (!nArgs) {
		ErrorMessage("SnmpTrapPlugin: No SnmpTrap Args found\n");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin");
	} else {
		/*
		 * We have got the facility part remaining part contains
		 * the sensorID , and SNMP related options
		 */

		*nArgs = 0;
		nArgs++;
	}

	if (facility != NULL) {
		if (!strncasecmp(facility, "alert", 5)) {
			data->facility = facility;
		} else {
			ErrorMessage("SnmpTrapPlugin: First argument needs to be alert\n");
			SnmpTrapUsage();
			FatalError("Quitting in SnmpTrapPlugin");
		}
	} else {
		ErrorMessage("SnmpTrapPlugin: cannot find first argument\n");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin");
	}

	while (*nArgs == ' ' || *nArgs == '\t') {
		nArgs++;
		if (!(*nArgs))
			break;
	}
	if (!(*nArgs)) {
		ErrorMessage("SnmpTrapPlugin: cant find sensorID \n");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin");
	}
	sensorPtr = nArgs;
	args = nArgs;
	nArgs = index(args, ',');
	if (!nArgs) {
		ErrorMessage("SnmpTrapPlugin: cant find sensorID \n");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin");
	} else {
		/*
		 * We have got the sensorID  the remaining part contains
		 * the SNMP related options
		 */

		*nArgs = 0;
		nArgs++;
	}

	sensorID = atol(sensorPtr);
	data->sensorID = sensorID;
	if (!data->sensorID) {
		ErrorMessage("SnmpTrapPlugin: Incorrect SensorID: %s", sensorPtr);
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin\n");
	}

	/*
	 * Check if Compact message flag is set
	 */
	while (*nArgs == ' ' || *nArgs == '\t') {
		nArgs++;
		if (!(*nArgs))
			break;
	}
	if (*nArgs) {
		args = nArgs;
		nArgs = index(args, ',');
		if (nArgs) {
			while (nArgs && (*args == 'C' || *args == 'c' || *args == 'P'
					|| *args == 'p' || *args == 'M' || *args == 'm' || *args
					== 'S' || *args == 's')) {
				switch (*args) {
				case 'C':
				case 'c':
					/*
					 * The Compact Alerts Flag is set
					 * SensorID and AlertID will NOT be sent as
					 * separate MOs in the trap. They will be inferred
					 * the OIDs of the constituent MOs.
					 */

					data->compact = 1;
					break;
				case 'P':
				case 'p':
					data->pPrint = 1;
					break;
				case 'M':
				case 'm':
					if (data->pPrint) {
						data->hashAlgorithm = USE_MD5;
						data->hashLength = HASHLEN_MD5;
					} else {
						ErrorMessage("SnmpTrapPlugin: Params error: %s (m may only follow p)", args);
//								" m may only follow p");
						SnmpTrapUsage();
						FatalError("Quitting in SnmpTrapPlugin\n");

					}
					break;
				case 'S':
				case 's':
					if (data->pPrint) {
						data->hashAlgorithm = USE_SHA1;
						data->hashLength = HASHLEN_SHA1;
					} else {
						ErrorMessage("SnmpTrapPlugin: Params error: %s (m may only follow p)", args);
//								" m may only follow p");
						SnmpTrapUsage();
						FatalError("Quitting in SnmpTrapPlugin\n");

					}
					break;
				default:
					ErrorMessage("SnmpTrapPlugin: Params error: %s (m may only follow p)", args);
//								" m may only follow p");
					SnmpTrapUsage();
					FatalError("Quitting in SnmpTrapPlugin\n");
				}
				args++;
			}
			*nArgs = 0;
			nArgs++;
		} else {
			nArgs = args;
		}
	}

	if (data->pPrint && (!data->hashAlgorithm)) {
		data->hashAlgorithm = USE_MD5; /* The default algorithm */
		data->hashLength = HASHLEN_MD5; /* The default           */
	}

	argc = CountSnmpArgs(nArgs, (char *) &Argv[0]);
	if (argc < 2) {
		ErrorMessage("SnmpTrapPlugin: Not enough parameters ");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin\n");
	}
	if (!strncasecmp(Argv[0], "inform", 6)) {
		data->trapOrInform = 1;
	} else if (!strncasecmp(Argv[0], "trap", 4)) {
		data->trapOrInform = 0;
	} else {
		ErrorMessage("SnmpTrapPlugin: expected {inform | trap } ");
		ErrorMessage("                got %s ", Argv[0]);
		ErrorMessage("                Assuming trap.            ");
		/*       SnmpTrapUsage();    */
	}
	/*
	 * Parse all the SNMP Options that are given on the command line
	 */
#ifdef HAVE_NETSNMP
	nargc = snort_snmp_parse_args(argc, Argv, &(data->session), NULL, NULL);
#else
	nargc = snmp_parse_args (argc, Argv, &(data->session), NULL, NULL);
#endif
	if (nargc < 0) {
		ErrorMessage("SnmpTrapPlugin:  Insufficient SnmpTrap parameters ");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin\n");

	}
	if (data->session.peername) { /* net-snmp accepts port specification only at the end
	 of the address separated by a colon.
	 In ucd-snmp this was done using the -p flag.
	 This incompatibility open up a can of worms.
	 */
		lastColon = strrchr(data->session.peername, ':');
		cPtr = lastColon;
		if (lastColon && !((tPtr = strchr(cPtr, ':')) && (strchr(++tPtr, ':')))) {
			*lastColon = 0;
			tInfo = gethostbyname(data->session.peername);
#ifdef HAVE_NETSNMP
			/* the processing is already done in snort_snmp_parse_args() */
			*lastColon = ':';
#else     

			tmpPort=atoi(lastColon+1);
			if ((tmpPort < 1) || (tmpPort > 65535))
			{
				ErrorMessage("Invalid port number after hostName\n");
				FatalError("Quitting in SnmpTrapPlugin\n");;
			}
			data->session.remote_port=tmpPort;
#endif
		} else
			tInfo = gethostbyname(data->session.peername);
		if (tInfo == NULL) {
			ErrorMessage("SnmpTrapPlugin: Unresolvable Trap destination : %s",
					data->session.peername);
			SnmpTrapUsage();
			FatalError("Quitting in SnmpTrapPlugin\n");
		}
	} else {
		ErrorMessage("SnmpTrapPlugin: Insufficient SNMP params");
		SnmpTrapUsage();
		FatalError("Quitting in SnmpTrapPlugin\n");
	}
	memmove(&data->trapdInfo.sin_addr, tInfo->h_addr, tInfo->h_length);
	data->addrLen = tInfo->h_length;
	if (!data->session.remote_port)
		data->session.remote_port = 162;
	data->trapdPort = data->session.remote_port;
	return (data);
}

/* 
 * Count the number of SnmpArguments presents
 */
int CountSnmpArgs(char *Args, char** Argvs) {
	int Count;
	int QuotedString;
	char *Token;

	QuotedString = 0;
	Count = 0;

	if (!(*Args)) {
		*Argvs = NULL;
		return (Count);
	}
	Token = strtok(Args, " ");

	while (Token) {
		if (QuotedString) {

			if (*(Token + strlen(Token) - 1) == '"') {
				QuotedString = 0;
			} else {
				*(Token + strlen(Token)) = ' ';
			}
		} else {
			Count++;
			*Argvs = Token;
			Argvs++;
			if (*Token == '"') {
				if (*(Token + strlen(Token) - 1) != '"') {
					*(Token + strlen(Token)) = ' ';
				}
			}
		}
		Token = strtok(NULL, " ");

	}
	return Count;
}

void SpoSnmpTrap(Packet *p, char *msg, void *arg, Event *event) {
	return startIDWS(p, msg, event);
}

void SnmpTrapCleanExitFunc(int signal, void *arg) {
	SnmpTrapData *SnmpData;
	SnmpData = (SnmpTrapData *) arg;
	/* close clean and free */
	DEBUG_WRAP(DebugMessage(DEBUG_LOG, "SnmpTrapCleanExitFunc\n"););
	if (SnmpData->sensorVersion) {
		free(SnmpData->sensorVersion);
	}
	if (&(SnmpData->session)) {
		snmp_close(&SnmpData->session);
	}
	/*
	 * Would be nice if we could save the AlertID in some non-volatile
	 * Storage
	 */
}
#ifdef SNORT_RELOAD
void SnmpTrapRestartFunc(int signal, void *arg) {

	SnmpTrapData *SnmpData;
	SnmpData = (SnmpTrapData *) arg;
	/* close clean and free */
	DEBUG_WRAP(DebugMessage(DEBUG_LOG,"SnmpTrapRestartFunc\n"););
	if (SnmpData->sensorVersion) {
		free(SnmpData->sensorVersion);
	}
	if (&(SnmpData->session)) {
		snmp_close(&SnmpData->session);
	}
}
#endif
void InitSnmpSession(SnmpTrapData *SnmpData) {

	struct snmp_session *session;
	int inform;
	session = &(SnmpData->session);
	inform = 1; /* Need to set this from the options line */

	SOCK_STARTUP;

	session->callback = snmp_input;
	session->callback_magic = NULL;
	if (session->remote_port == SNMP_DEFAULT_REMPORT || session->remote_port
			== SNMP_PORT)
		session->remote_port = SNMP_TRAP_PORT;

	if (session->version == SNMP_VERSION_3 && !inform) {
		setup_engineID(NULL, NULL);

		if (session->securityEngineIDLen == 0 || session->securityEngineID
				== NULL) {
			session->securityEngineID = snmpv3_generate_engineID(
					&session->securityEngineIDLen);
		}
		if (session->contextEngineIDLen == 0 || session->contextEngineID
				== NULL) {
			session->contextEngineID = snmpv3_generate_engineID(
					&session->contextEngineIDLen);
		}

		if (session->engineBoots == 0) {
			session->engineBoots = 1;
		}
		if (session->engineTime == 0) {
			session->engineTime = get_uptime();
		}
	}

	init_snmp("snmpapp");

}

/* purpose   : SNMPinform is sent to the trapd program in this
 method
 parameter : Packet *p, char *msg
 return    : void
 */
void sendSNMPInform(Packet *p, char *msg, long AlertID, SnmpTrapData *SnmpData,
		Event *event) {
	int Result;

	Result = sendInform(p, msg, AlertID, SnmpData, event);
}

/* purpose   : startIDWS() method is called from the snortnet
 for each alert raised according to the rules
 file
 parameter : packet, msg, Event
 return    :
 */

void startIDWS(Packet *p, char *msg, Event *event) {
	/*
	 if    (!p)
	 {
	 ErrorMessage("SnortSnmp: Null packet with msg %s \n",
	 msg?msg:"NULL");
	 return;
	 }
	 */

	static unsigned long lastSecond;
	static int alertsInThisSec;
	static int alertsIgnored;
	struct timeval timeNow;
	if (maxAlertsInOneSec > 0) {
		gettimeofday(&timeNow, NULL);
		if (timeNow.tv_sec == lastSecond) {
			if (alertsInThisSec >= maxAlertsInOneSec) {
				alertsIgnored++;
				printf("%s tot = %d m = %d, tN = %lu, tL = %lu \n",
						"ignoring alert", alertsInThisSec, maxAlertsInOneSec,
						timeNow.tv_sec, lastSecond);
				return;
			} else {
				/* do nothing */
				alertsInThisSec++;
			}

		} else {
			alertsInThisSec = 1;
			lastSecond = timeNow.tv_sec;
		}
	}
//	printf("%s tot = %d m = %d, tN = %lu, tL = %lu \n", "sending alert",
//			alertsInThisSec, maxAlertsInOneSec, timeNow.tv_sec, lastSecond);
	alertID++;
	sendSNMPInform(p, msg, alertID, &SnmpData, event);
	return;
}

oid objid_enterprise[] = { 1, 3, 6, 1, 4, 1, 3, 1, 1 };
oid objid_sysdescr[] = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
oid objid_sysuptime[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
oid objid_snmptrap[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };

int snmp_input(int operation, struct snmp_session *session, int reqid,
		struct snmp_pdu *pdu, void *magic) {
	return 1;
}

in_addr_t parse_address(char *address) {
	in_addr_t addr;
	struct sockaddr_in saddr;
	struct hostent *hp;

	if ((addr = inet_addr(address)) != -1)
		return addr;
	hp = gethostbyname(address);
	if (hp == NULL) {
		ErrorMessage("unknown host: %s\n", address);
		exit(1);
	} else {
		memcpy(&saddr.sin_addr, hp->h_addr, hp->h_length);
		return saddr.sin_addr.s_addr;
	}

}

/* 
 * We may have large URLs !! 
 */
#define VALSTRINGLEN  512
#define ZERO          "0"
int sendInform(Packet *p, char *msg, long AlertID, SnmpTrapData *SnmpData,
		Event *event) {
	struct snmp_session *session, *ss;
	struct snmp_pdu *pdu, *response;
	static int TrapdUnreachWarningSent = 0;
	int arg;
	int status;
	int inform;
	int Result;
	int sourceAddressType;
	int targetAddressType;
	long sensorID;
	long sysuptime;
	long Value;
	char csysuptime[20];
	char ValString[VALSTRINGLEN];
	char *trap = NULL;
	char timeNtpStamp[32];
	char *myOID;
	// Port scan related global variables
	char *scanSource;
	long scanDuration;
	int scannedHosts;
	int TCPScanCount;
	int UDPScanCount;
	int scanType;
	int scanStatus;

	struct timeval unixStamp;
	/*
	 * The hashBuf contains
	 *              the hash in hexdecimal notation
	 *              a colon ':'
	 *              a zero-padded 3 digit packet length
	 *              a null termination character
	 *              a colon ':'
	 *              a zero-padded 3 digit ttl
	 *              a null termination character
	 */
#define HASHBUFSIZE SnmpData->hashLength * 2 + 1 + 8 
	char hashBuf[HASHBUFSIZE];
	ClassType *class_ptr = NULL;
	ReferenceNode *refNode = NULL;

	/* DumpRuleChains();   */
	sensorID = SnmpData->sensorID;
	gettimeofday(&unixStamp, NULL);
	/*
	 * Check if we are trying to send a trap for an
	 *       icmp-destination unreachable packet to the
	 *       trap receiver
	 * Attempting to send traps/informs (to an unreachable receiver) about
	 * ICMP unreachable packets to the trap receiver - leads to a loop of
	 * more traps and consequent ICMP unreachable packets. This will result
	 * in an attack on  system itself and should be avoided!
	 */
	if ((p) && (p->iph) && (inet_ntoa(GET_SRC_ADDR(p))) && (p->orig_iph)
			&& (p->orig_dp)) {
		if ((!memcmp((void *) &p->iph->ip_src,
				(void *) &SnmpData->trapdInfo.sin_addr, SnmpData->addrLen))
				&& (!memcmp((void *) &p->orig_iph->ip_dst,
						(void *) &SnmpData->trapdInfo.sin_addr,
						SnmpData->addrLen)) && (p->orig_dp
				== SnmpData->trapdPort) && (!strcmp(
				protocol_names[p->iph->ip_proto], "ICMP"))) {
			if (TrapdUnreachWarningSent == 1)
				return (1);
			ErrorMessage("+============= !! ATTENTION !! ===============+\n");
			ErrorMessage("| Snort detected ICMP packets indicating  the |\n");
			ErrorMessage("| Trap receiver is unreachable.               |\n");
			ErrorMessage("| ICMP packet originated from %s               \n",
					inet_ntoa(GET_SRC_ADDR(p)));
//			ErrorMessage("|      orig IPDgram src/dst =  %s/", inet_ntoa(
//					p->orig_iph->ip_src));
//			ErrorMessage("%s           \n", inet_ntoa(p->orig_iph->ip_dst));
//			ErrorMessage("|      orig IPDgram Protocol/dstPort =  %s/%d  \n",
//					protocol_names[p->orig_iph->ip_proto], p->orig_dp);
			ErrorMessage("| Snort will not attempt to send such alerts  |\n");
			ErrorMessage("| to the Trap Receiver.                       |\n");
			ErrorMessage("| You need to check that the Trap receiver is |\n");
			ErrorMessage("| running and snort is properly configured.   |\n");
			ErrorMessage("| [This message will be displayed only once.] |\n");
			TrapdUnreachWarningSent = 1;
			return (1);
		}
	}
	snprintf(timeNtpStamp, sizeof(timeNtpStamp), "%ld.%6ld", unixStamp.tv_sec,
			unixStamp.tv_usec);

	session = &(SnmpData->session);
	ss = NULL;
	inform = SnmpData->trapOrInform;

	ss = snmp_open(session);
	if (ss == NULL) {
		/* diagnose snmp_open errors with the input struct snmp_session pointer */
		snmp_sess_perror("snmptrap", session);
		SOCK_CLEANUP;
		return (1);
	}
	arg = 0;
	if (session->version == SNMP_VERSION_1) {
		ErrorMessage("Sorry! Version 1 traps are not supported now \n");
		return (1);
	}
	if (event->sig_generator == GENERATOR_PSNG) {
		getScanDetails(p, msg, event, &scanSource, &scanDuration,
				&scannedHosts, &TCPScanCount, &UDPScanCount, &scanType,
				&scanStatus);
	}
	/*
	 * The SysUpTime
	 */

	pdu = snmp_pdu_create(inform ? SNMP_MSG_INFORM : SNMP_MSG_TRAP2);
	sysuptime = get_uptime();
	snprintf(csysuptime, sizeof(csysuptime), "%ld", sysuptime);
	trap = csysuptime;
	snmp_add_var(pdu, objid_sysuptime, sizeof(objid_sysuptime) / sizeof(oid),
			't', trap);
	/*
	 * The trap OID
	 */
	if (event->sig_generator == GENERATOR_PSNG)
	{
		myOID = _OID_sidaAlertScanStatus;
	}
	else
	{
		myOID = _OID_sidaAlertGenericOID;
	}
	myOID = _OID_sidaAlertGenericOID;
	if (snmp_add_var(pdu, objid_snmptrap, sizeof(objid_snmptrap) / sizeof(oid),
			'o', myOID) != 0) {
		snmp_perror(_OID_sidaAlertGenericOID);
		SOCK_CLEANUP;
		return (1);
	}
	/*
	 * Snort Version is not included in the notification anymore !
	 */
#if 0

	/*
	 * The SensorVersion
	 */
	Result = ParseSensorOidAndAddToPdu( SENSORVERSION, sensorID,
			SnmpData->sensorVersion, pdu);

	if (Result)
	{
		SOCK_CLEANUP;
		return (Result);
	}
#endif
	/*
	 * The AlertTimeStamp
	 */
	Result = ParseOidAndAddToPdu(ALERTTIMESTAMP, sensorID, AlertID,
			timeNtpStamp, pdu);

	if (Result) {
		SOCK_CLEANUP;
		return (Result);
	}

	/*
	 * The Msg
	 */
	if (!msg) {
		ValString[0] = 0;
	} else {
		strncpy(ValString, msg, VALSTRINGLEN - 1);
		ValString[VALSTRINGLEN - 1] = 0;
	}

	Result = ParseOidAndAddToPdu(ALERTMSG, sensorID, AlertID, ValString, pdu);
	if (Result) {
		SOCK_CLEANUP;
		return (Result);
	}

	/*
	 * The Classification that is the "Impact" in IDMEF lingo
	 */
	if (otn_tmp) {
		class_ptr = otn_tmp->sigInfo.classType;
	}
	if (class_ptr && class_ptr->type) {
		Value = getImpactCode(class_ptr->type);
	} else {
		Value = 1; /* unknown */
	}
	snprintf(ValString, sizeof(ValString), "%ld", Value);
	Result
			= ParseOidAndAddToPdu(ALERTIMPACT, sensorID, AlertID, ValString,
					pdu);
	if (Result) {
		SOCK_CLEANUP;
		return (Result);
	}

	/*
	 * Get the PortScan Mandatory Objects in
	 */
	if (event->sig_generator == GENERATOR_PSNG)
	{
		/*
		 * The Scan type; This is 'stealth or other' classification.
		 */
		if (scanType != 2) /* Type is Not stealth */
		scanType = 1;
		snprintf (ValString, sizeof(ValString), "%d", scanType);
		Result = ParseOidAndAddToPdu( ALERTSCANTYPE, sensorID,
				AlertID, ValString, pdu);
		if (Result)
		{
			SOCK_CLEANUP;
			return (Result);
		}
		/*
		 * The Scan Status
		 */
		snprintf (ValString, sizeof(ValString), "%d", scanStatus);
		Result = ParseOidAndAddToPdu( ALERTEVENTSTATUS, sensorID,
				AlertID, ValString, pdu);
		if (Result)
		{
			SOCK_CLEANUP;
			return (Result);
		}

	}

	/*****  +++++++++++++ Now the Optional objects +++++++++++++ ******/

	if (SnmpData->compact) {
		/*
		 * The SensorID - we are not including this now as this may be
		 * easily inferred from the other OIDs in the trap | inform.
		 */
		/*
		 * The AlertID - we are not including this now as this may be
		 * easily inferred from the other OIDs in the trap | inform.
		 */
	} else {
		snprintf(ValString, sizeof(ValString), "%d", SnmpData->sensorID);
		Result = ParseSensorOidAndAddToPdu(SENSORID, sensorID, ValString, pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
		snprintf(ValString, sizeof(ValString), "%ld", AlertID);

		Result
				= ParseOidAndAddToPdu(ALERTID, sensorID, AlertID, ValString,
						pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 * Actions Taken (We are not supplying the value now - this is just a
	 * place holder!)
	 */
	if (SnmpData->compact) {
	} else {
		/*snprintf (ValString, sizeof(ValString), "%d", 0); */
		ValString[0] = 0;
		Result = ParseSensorOidAndAddToPdu(ALERTACTIONSTAKEN, sensorID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 * The AlertMoreInfo
	 */
	ValString[0] = 0;
	if (otn_tmp) {
		refNode = otn_tmp->sigInfo.refs;
		while (refNode) {
			if (refNode->system && refNode->system->url) {
				strncat(ValString, refNode->system->url, VALSTRINGLEN - 1);
				ValString[VALSTRINGLEN - 1] = 0;
				strncat(ValString, refNode->id, VALSTRINGLEN
						- strlen(ValString) - 1);
				ValString[VALSTRINGLEN - 1] = 0;
				strncat(ValString, ", ", VALSTRINGLEN - strlen(ValString) - 1);
				ValString[VALSTRINGLEN - 1] = 0;
			}
			refNode = refNode->next;
		}
	}
	if (!ValString[0] && !(SnmpData->compact))
		strncpy(ValString, " ", sizeof(ValString) - 1);
	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTMOREINFO, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 * The Sensor address - only if we know it  or, if detailed alert required !
	 */
	if (sensorAddress || !(SnmpData->compact)) {
		/*
		 * The SensorAddressType
		 */
		if (sensorAddress)
			snprintf(ValString, sizeof(ValString), "%d", sensorAddressType);
		else {
			strncpy(ValString, ZERO, sizeof(ValString) - 1);/*Unknown or not applicable */
			ValString[VALSTRINGLEN - 1] = 0;
		}
		Result = ParseOidAndAddToPdu(SENSORADDRESSTYPE, sensorID, AlertID,
				ValString, pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}

		/*
		 * The SensorAddress
		 */
		if (sensorAddress) {
			strncpy(ValString, sensorAddress, sizeof(ValString) - 1);
			ValString[VALSTRINGLEN - 1] = 0;
		} else
			ValString[0] = 0; /* Zero Length string */
		Result = ParseOidAndAddToPdu(SENSORADDRESS, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}
	/*
	 * Source IP address and type
	 */
	if ((p) && (p->iph) && (inet_ntoa(GET_SRC_ADDR(p)))) {
		/*
		 * The AlertSrcAddressType
		 */
		if (IP_VER(p->iph) == 4) {
			sourceAddressType = 1;
		} else if (IP_VER(p->iph) == 6) {
			sourceAddressType = 2;
		} else {
			sourceAddressType = 0;
		}
		snprintf(ValString, sizeof(ValString), "%d", sourceAddressType);
		Result = ParseOidAndAddToPdu(ALERTSRCADDRESSTYPE, sensorID, AlertID,
				ValString, pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}

		/*
		 * The AlertSrcAddress
		 */
		Result = ParseOidAndAddToPdu(ALERTSRCADDRESS, sensorID, AlertID,
				inet_ntoa(GET_SRC_ADDR(p)), pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}
	else if (event->sig_generator == GENERATOR_PSNG)
	{
		/* sfPortscan now generates a pseudo packet on which this alert is
		 * fired. Therefore, port scan incident does not take us to here.
		 */
		/*
		 *  Set the type to IPv4 till we find a way to handle other
		 *  Address types.
		 */
		if (strlen(scanSource))
		{
			sourceAddressType = 1;
		}
		else
		{
			sourceAddressType = 0; /* unknown or not applicable */
		}
		snprintf (ValString, sizeof(ValString), "%d", sourceAddressType);
		Result = ParseOidAndAddToPdu( ALERTSRCADDRESSTYPE, sensorID,
				AlertID, ValString, pdu);

		if (Result)
		{
			SOCK_CLEANUP;
			return (Result);
		}
		/*
		 * The ScanSourceAddress
		 */
		if (strlen(scanSource))
		{
			Result = ParseOidAndAddToPdu( ALERTSRCADDRESS, sensorID, AlertID,
					scanSource, pdu);
		}
		else
		{
			ValString[0] = 0; /* zero length string */
			Result = ParseOidAndAddToPdu( ALERTSRCADDRESS, sensorID, AlertID,
					ValString, pdu);
		}
		if (Result)
		{
			SOCK_CLEANUP;
			return (Result);
		}
	}
	else if (!SnmpData->compact) {
		strncpy(ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
		Result = ParseOidAndAddToPdu(ALERTSRCADDRESSTYPE, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
		ValString[0] = 0; /* Zero length string        */
		Result = ParseOidAndAddToPdu(ALERTSRCADDRESS, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 * Destination IP address and type
	 */
	if ((p) && (p->iph) && (inet_ntoa(GET_DST_ADDR(p)))) {
		/*
		 * The AlertDstAddressType
		 */
		if (IP_VER(p->iph) == 4) {
			targetAddressType = 1;
		} else if (IP_VER(p->iph) == 6) {
			targetAddressType = 2;
		} else {
			targetAddressType = 0;
		}

		snprintf(ValString, sizeof(ValString), "%d", targetAddressType);
		Result = ParseOidAndAddToPdu(ALERTDSTADDRESSTYPE, sensorID, AlertID,
				ValString, pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}

		/*
		 * The AlertDstAddress
		 */
		Result = ParseOidAndAddToPdu(ALERTDSTADDRESS, sensorID, AlertID,
				inet_ntoa(GET_DST_ADDR(p)), pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	else if (!SnmpData->compact) {
		strncpy(ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
		Result = ParseOidAndAddToPdu(ALERTDSTADDRESSTYPE, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
		ValString[0] = 0; /* Zero length string        */
		Result = ParseOidAndAddToPdu(ALERTDSTADDRESS, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}
	/*
	 * The AlertSrcPort
	 */
	if (p && p->sp) {
		snprintf(ValString, sizeof(ValString), "%d", p->sp);
	} else if (!SnmpData->compact) {
		strncpy(ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else
		ValString[0] = 0;

	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTSRCPORT, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 * The AlertDstPort
	 */
	if (p && p->dp) {
		snprintf(ValString, sizeof(ValString), "%d", p->dp);
	} else if (!SnmpData->compact) {
		strncpy(ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else
		ValString[0] = 0;

	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTDSTPORT, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 * The Priority field does not exist in IDMEF world
	 *              But it exists in the Snort system !
	 */

	if (otn_tmp) {
		class_ptr = otn_tmp->sigInfo.classType;
	}
	if (class_ptr) {
		Value = class_ptr->priority;
		snprintf(ValString, sizeof(ValString), "%ld", Value);
	} else if (!SnmpData->compact) {
		Value = -1; /* unknown */
		snprintf(ValString, sizeof(ValString), "%ld", Value);
	} else {
		ValString[0] = 0;
	}
	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTEVENTPRIORITY, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	if (event->sig_generator == GENERATOR_PSNG)
	{
		/*
		 * The following objects are already fetched
		 */
		/*
		 getScanDetails(msg,  event, &scanSource, &scanDuration, &scannedHosts,
		 &TCPScanCount, &UDPScanCount, &scanType, &scanStatus );
		 */

		/*
		 * The ScanDuration
		 */
		if (scanDuration >= 0 )
		{
			snprintf (ValString, sizeof(ValString), "%ld", scanDuration );
		}
		else if (!SnmpData->compact)
		{
			strncpy (ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
			ValString[VALSTRINGLEN -1] = 0;
		}
		else ValString[0] = 0;

		if (ValString[0])
		{
			Result = ParseOidAndAddToPdu( ALERTSCANDURATION, sensorID,
					AlertID, ValString, pdu);
			if (Result)
			{
				SOCK_CLEANUP;
				return (Result);
			}
		}

		/*
		 * The ScannedHosts
		 */
		if (scannedHosts >= 0 )
		{
			snprintf (ValString, sizeof(ValString), "%d", scannedHosts);
		}
		else if (!SnmpData->compact)
		{
			strncpy (ValString, ZERO, VALSTRINGLEN -1 ); /* Unknown or not applicable */
			ValString[VALSTRINGLEN -1] = 0;
		}
		else
		{
			ValString[0] = 0;
		}

		if (ValString[0])
		{
			Result = ParseOidAndAddToPdu( ALERTSCANNEDHOSTS, sensorID,
					AlertID, ValString, pdu);
			if (Result)
			{
				SOCK_CLEANUP;
				return (Result);
			}
		}

		/*
		 * The Number of TCP connections
		 */
		if (TCPScanCount >= 0)
		{
			snprintf (ValString, sizeof(ValString), "%d", TCPScanCount);
		}
		else if (!SnmpData->compact)
		{
			strncpy (ValString, ZERO, VALSTRINGLEN -1 ); /* Unknown or not applicable */
			ValString[VALSTRINGLEN -1] = 0;
		}

		else
		{
			ValString[0] = 0;
		}
		if (ValString[0])
		{
			Result = ParseOidAndAddToPdu( ALERTTCPSCANCOUNT, sensorID,
					AlertID, ValString, pdu);
			if (Result)
			{
				SOCK_CLEANUP;
				return (Result);
			}
		}
		/*
		 * The Number of UDP Scans
		 */
		if (UDPScanCount >= 0)
		{
			snprintf (ValString, sizeof(ValString), "%d", UDPScanCount);
		}
		else if (!SnmpData->compact)
		{
			strncpy (ValString, ZERO, VALSTRINGLEN -1 ); /* Unknown or not applicable */
			ValString[VALSTRINGLEN -1] = 0;
		}
		else
		{
			ValString[0] = 0;
		}

		if (ValString[0])
		{
			Result = ParseOidAndAddToPdu( ALERTUDPSCANCOUNT, sensorID,
					AlertID, ValString, pdu);
			if (Result)
			{
				SOCK_CLEANUP;
				return (Result);
			}
		}
	}

	/*
	 * The AlertSrcMAcAddress
	 */
	if (p && p->eh) {
		snprintf(ValString, sizeof(ValString), "%02x %02x %02x %02x %02x %02x",
				*(p->eh->ether_src + 0), *(p->eh->ether_src + 1),
				*(p->eh->ether_src + 2), *(p->eh->ether_src + 3),
				*(p->eh->ether_src + 4), *(p->eh->ether_src + 5));
		ValString[18] = 0;
	} else if (!SnmpData->compact) {
		strncpy(ValString, "000000000000", VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else {
		ValString[0] = 0;
	}

	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTSRCMACADDRESS, sensorID, AlertID,
				ValString, pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}
	/*
	 * The AlertDstMacAddress
	 */
	if (p && p->eh) {
		snprintf(ValString, sizeof(ValString), "%02x %02x %02x %02x %02x %02x",
				*(p->eh->ether_dst + 0), *(p->eh->ether_dst + 1),
				*(p->eh->ether_dst + 2), *(p->eh->ether_dst + 3),
				*(p->eh->ether_dst + 4), *(p->eh->ether_dst + 5));
		ValString[18] = 0;
	} else if (!SnmpData->compact) {
		strncpy(ValString, "000000000000", VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else {
		ValString[0] = 0;
	}
	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTDSTMACADDRESS, sensorID, AlertID,
				ValString, pdu);

		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}
	/*
	 *    The AlertProto
	 */
	if (p && p->iph && p->iph->ip_proto) {
		snprintf(ValString, sizeof(ValString), "Protocol: %s",
				protocol_names[p->iph->ip_proto]);
	} else if (!SnmpData->compact) {
		strncpy(ValString, " ", VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else {
		ValString[0] = 0;
	}

	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTPROTO, sensorID, AlertID, ValString,
				pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}
	/*
	 *    The AlertRuleID
	 */
	if (event && event->sig_id) {
		snprintf(ValString, sizeof(ValString), "%u", event->sig_id);
	} else if (!SnmpData->compact) {
		strncpy(ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else {
		ValString[0] = 0;
	}

	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTRULEID, sensorID, AlertID, ValString,
				pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	/*
	 *    The AlertRevision
	 */
	if (event && event->sig_rev) {
		snprintf(ValString, sizeof(ValString), "%u", event->sig_rev);
	} else if (!SnmpData->compact) {
		strncpy(ValString, ZERO, VALSTRINGLEN - 1); /* Unknown or not applicable */
		ValString[VALSTRINGLEN - 1] = 0;
	} else {
		ValString[0] = 0;
	}

	if (ValString[0]) {
		Result = ParseOidAndAddToPdu(ALERTRULEREVISION, sensorID, AlertID,
				ValString, pdu);
		if (Result) {
			SOCK_CLEANUP;
			return (Result);
		}
	}

	if (p && p->iph && SnmpData->pPrint) {
		int IpVer;
		IpVer = IP_VER(p->iph);

		hash_func = SnmpData->hashAlgorithm;
		hash_length = SnmpData->hashLength;
		switch (IpVer) {
		case 4: /* IPv4 packets */
			ip_print_hashing((struct pcap_pkthdr32 *)p->pkth, (u_char *) p->pkt, hashBuf, SnmpData);
			break;
#ifdef INET6
		case 6: /* IPv6 packets */
			ipv6_print_hashing((struct pcap_pkthdr32 *)p->pkth, (u_char *) p->pkt, hashBuf, SnmpData);
			break;
#endif
		default:
			hashBuf[0] = 0;
		}

		if (hashBuf[0]) {
			Result = ParseOidAndAddToPdu(ALERTPACKETPRINT, sensorID, AlertID,
					hashBuf, pdu);
			if (Result) {
				SOCK_CLEANUP;
				return (Result);
			}
		}
		hashBuf[0] = 0;
	}
	if (inform) {
		status = snmp_synch_response(ss, pdu, &response);
	} else {
		status = snmp_send(ss, pdu) == 0;
	}
	if (status) {
		snmp_sess_perror(inform ? "snmpinform" : "snmptrap", ss);
		/*
		 * The pdu is already freed - we do not need to free it again
		 */
		/*
		 snmp_free_pdu(pdu);
		 */
		/*
		 * We go into trap mode if there was a time out. Otherwise it
		 * may ruin Snort's happiness!
		 */
		if (SnmpData->trapOrInform) {
			ErrorMessage("+============= !! ATTENTION !! ===============+\n");
			ErrorMessage("| Snort was configured to send 'Informs' BUT  |\n");
			ErrorMessage("| there is no response from the Trap receiver |\n");
			ErrorMessage("| You will need to check that the SnmpTrapd is|\n");
			ErrorMessage("| alive and kicking on port %d of %s \n",
					session->remote_port, session->peername);
			ErrorMessage("| Snort will switch to TRAP mode.             |\n");
			ErrorMessage("| You will need to restart Snort to revert to |\n");
			ErrorMessage("| INFORM mode.                                |\n");
			ErrorMessage("+============= !! ATTENTION !! ===============+\n");
			SnmpData->trapOrInform = 0;
		}
	} else if (inform) {
		snmp_free_pdu(response);
	}

	snmp_close(ss);
	SOCK_CLEANUP;
	return (0);
}

int ParseSensorOidAndAddToPdu(int OIDIndex, long SensorID, char * ValString,
		struct snmp_pdu *pdu) {
	char tmpBuf[1024];
	oid name[MAX_OID_LEN];
	int name_length;
	char type;
	name_length = MAX_OID_LEN;

	snprintf(tmpBuf, sizeof(tmpBuf), "%s.%ld",
			SnmpTrapMOs[OIDIndex][OID_INDEX], SensorID);
	if (!snmp_parse_oid(tmpBuf, name, &name_length)) {
		snmp_perror(tmpBuf);
		SOCK_CLEANUP;
		return (1);
	}

	type = (int) *(SnmpTrapMOs[OIDIndex][TYPE_INDEX]);
	if (snmp_add_var(pdu, name, name_length, type, ValString) != 0) {
		snmp_perror(SnmpTrapMOs[OIDIndex][OID_INDEX]);
		SOCK_CLEANUP;
		return (1);
	}
	return (0);
}

int ParseOidAndAddToPdu(int OIDIndex, long SensorID, long AlertID,
		char * ValString, struct snmp_pdu *pdu) {
	char tmpBuf[1024];
	oid name[MAX_OID_LEN];
	int name_length;
	char type;
	name_length = MAX_OID_LEN;

	snprintf(tmpBuf, sizeof(tmpBuf), "%s.%ld.%ld",
			SnmpTrapMOs[OIDIndex][OID_INDEX], SensorID, AlertID);
	if (!snmp_parse_oid(tmpBuf, name, &name_length)) {
		snmp_perror(tmpBuf);
		SOCK_CLEANUP;
		return (1);
	}

	type = (int) *(SnmpTrapMOs[OIDIndex][TYPE_INDEX]);
	if (snmp_add_var(pdu, name, name_length, type, ValString) != 0) {
		snmp_perror(SnmpTrapMOs[OIDIndex][OID_INDEX]);
		SOCK_CLEANUP;
		return (1);
	}
	return (0);
}

void SnmpTrapUsage() {
	puts("\nUSAGE: SnmpTrap plugin\n");

	puts(
			" output trap_snmp: alert, <sensorID>, [NotificationOptions] , {trap | inform} [SnmpOptions]  <snmptrapdAddress>\n");
	puts(" alert indicates that the plugin will use the alert facility");
	puts(" <sensorID>         indicates the sensorID assigned to this");
	puts("                    Sensor. SensorID is used to identify the");
	puts("                    origin of an {inform|trap} to the .");
	puts("                    receiver, It must be a non-zero integer.");
	puts(" [NotificationOptions]                                      ");
	puts(" [c,[p,[m|s]]]                                              ");
	puts("  c : Generate compact notifications.                       ");
	puts("     (Saves on bandwidth. By default this option is reset.  ");
	puts("  p : Generate a print of the offending packet.             ");
	puts("      By default this option is reset.                      ");
	puts("  m : Use the MD5 algorithm to generate the packet print.   ");
	puts("      By default this algorithm is used.                    ");
	puts("  s : Use the SHA1 algorithm to generate the packet print.  ");
	puts(" trap|inform        'trap' to generate snmp traps     ");
	puts("                    'inform' to generate snmp informs ");
	puts(" [SnmpOptions]      the various options that apply to the   ");
	puts("                    Snmp {inform|trap} generation.          ");
	puts("                    Examples are                            ");
	puts("                     -v 2c for Snmp version 2 community     ");
	puts("                      based {trap|inform} operation         ");
	puts("                     -p <portNo> to direct the {inform|trap} to  ");
	puts("                      <portNo> instead of the default port no 162");
	puts("                     -c <community> for the community to be ");
	puts("                      used if '-v 2c' is specified          ");
	puts("                    For details do a 'man snmpcmd'          ");
	puts(" <snmptrapdaddress> gives the address of snmptrap receiver  ");
}

/*
 * Map the Classification messages to Impact codes
 */

int getImpactCode(char *ClassificationName) {
	int index;
	for (index = 0; index < NOOFCLASSIFICATIONS; index++) {
		if (!(strcasecmp(Classifications[index], ClassificationName))) {
			return (++index);
		}
	}
	return (1); /* "Unknown" or "Other" classification */
}

/*
 * From the PortScan event get the corresponding ScanSource record
 */
/* apparently this is a tentative place holder */
void getScanDetails(Packet *p, char *msg, Event *event, char **oScanSource,
		long *scanDuration, int *scannedHosts, int *TCPScanCount,
		int *UDPScanCount, int *scanType, int *scanStatus) {
	fprintf(stderr, "getScanDetails: %s\n", msg);

	//    SourceInfo *currentSource;
	//    extern     ScanList *scanList;
	char *cPtr;
	struct timeval unixStamp;
#define SCANHOSTNAMESIZE 128
	static char scanSource[SCANHOSTNAMESIZE];

	scanSource[0] = 0;
	*oScanSource = &scanSource[0];
	*scanDuration = -1;
	*scannedHosts = -1;
	*TCPScanCount = -1;
	*UDPScanCount = -1;
	*scanType = -1;
	gettimeofday(&unixStamp, NULL);
	if (msg && (cPtr = strstr(msg, "(portscan) "))) {
		*scanStatus = 2;
		//          currentSource = scanList->lastSource;
		snprintf(scanSource, sizeof(scanSource), "%s",
				inet_ntoa(GET_SRC_ADDR(p)));
		// TODO: must find pv alternative
		//          if    (!pv.readmode_flag ){
		//                 *scanDuration =
		//                  unixStamp.tv_sec - currentSource->firstPacketTime.tv_sec;
		//          }

		//          *TCPScanCount = currentSource->numberOfTCPConnections;
		//          *UDPScanCount = currentSource->numberOfUDPConnections;
		//          *scannedHosts = currentSource->numberOfDestinations;
		//          if   (currentSource->stealthScanUsed)
		//               *scanType = 2;
		//          else
		*scanType = 1;
		return;
	}
#if 0
	if (event->sig_id == PORTSCAN_INTER_INFO)
	{
		*scanStatus = 3;
		currentSource = scanList->listHead;
		while (currentSource)
		{
			if (currentSource->event_id == event->event_reference )
			break;
			currentSource = currentSource->nextNode;
		}
		if (!currentSource)
		return;
		snprintf(scanSource, sizeof(scanSource), "%s", inet_ntoa(currentSource->saddr));
		if (!pv.readmode_flag )
		{
			*scanDuration =
			unixStamp.tv_sec - currentSource->firstPacketTime.tv_sec;
		}
		*TCPScanCount = currentSource->numberOfTCPConnections;
		*UDPScanCount = currentSource->numberOfUDPConnections;
		*scannedHosts = currentSource->numberOfDestinations;
		return;
	}
	if (event->sig_id == PORTSCAN_SCAN_END)
	{
		*scanStatus = 4;
		currentSource = scanList->listHead;
		while (currentSource)
		{
			if (currentSource->event_id == event->event_reference )
			break;
			currentSource = currentSource->nextNode;
		}
		if (!currentSource)
		return;
		snprintf(scanSource, sizeof(scanSource), "%s", inet_ntoa(currentSource->saddr));
		if (!pv.readmode_flag )
		{
			*scanDuration =
			unixStamp.tv_sec - currentSource->firstPacketTime.tv_sec;
		}
		*TCPScanCount = currentSource->totalNumberOfTCPConnections;
		*UDPScanCount = currentSource->totalNumberOfUDPConnections;
		*scannedHosts = currentSource->totalNumberOfDestinations;
		return;
	}
#endif
}

void ip_packet_hashing(const struct pcap_pkthdr32 *ch, u_char *Cp, size_t len,
		char *char_buf, SnmpTrapData *SnmpData) {
	int Count = 1;
	int i;
	register u_char *cp;
	register char *cBuf;
	register u_char *bBuf, *fBuf;
	char tBuf[5];
	u_char buf[SnmpData->hashLength + 1];
	/*char     char_buf[SnmpData->hashLength * 2 + 1] ; */
	int hashBufLen = SnmpData->hashLength * 2 + 1 + 8;
	u_char ttl;
	cp = Cp;

	cp += sizeof(struct ether_header); /* skip ether frame   */
	ttl = *(cp + TTLPOS);
	/*
	 * Mask the TTL value
	 */

	*(cp + TTLPOS) = (u_char) 0xff; /* change TTL's value to 0xff */

	/*
	 * Mask the check sum
	 */
	for (i = 0; i < CHECKSUMLEN; i++)
		*(i + CHECKSUMPOS + cp) = (u_char) 0xff;

	make_hash_value(SnmpData->hashAlgorithm, cp, (unsigned long) len, buf);

	*(cp + TTLPOS) = ttl; /* Put the TTL value back         */

	/*
	 * prepare the hexadecimal string representation of the hash
	 */

	cBuf = char_buf;
	bzero(cBuf, hashBufLen);
	bBuf = &buf[0];
	fBuf = bBuf + hash_length;
	for (; bBuf < fBuf; bBuf++, cBuf += 2) {
		snprintf((cBuf), hashBufLen - strlen(cBuf), "%02x", (int) *(bBuf));
	}
	snprintf(tBuf, sizeof(tBuf), ":%03u", len);
	strncat(cBuf, tBuf, hashBufLen - strlen(cBuf) - 1);
	*(cBuf + hashBufLen - 1) = 0;
	snprintf(tBuf, sizeof(tBuf), ":%03u", ttl);
	strncat(cBuf, tBuf, hashBufLen - strlen(cBuf) - 1);
	*(cBuf + hashBufLen - 1) = 0;
	{
		if (!(Count % 1) && DEBUG) {
			printf("%d:%06d %s %d\n", (ch->ts).tv_sec, (ch->ts).tv_usec,
					char_buf, Count);
		}

	}
	Count++;

}

void ip_print_hashing(const struct pcap_pkthdr32 *ch, u_char *cp, char *buf,
		SnmpTrapData * SnmpData) {
	register struct ip *ip;
	u_char protocol;
	size_t ip_length;
	ip = (struct ip *) (cp + sizeof(struct ether_header));

	/* determine the header length = ipheader + transport header */
	protocol = (u_char) ip->ip_p;

	switch (protocol) {
	case IPPROTO_TCP:
		/* printf("protocol TCP\n"); */
		ip_length = IP_HEADER_LENGTH + TCP_PROTOCOL_LENGTH;
		ip_packet_hashing(ch, cp, ip_length, buf, SnmpData);
		break;
	case IPPROTO_UDP:
		/* printf("protocol UDP\n"); */
		ip_length = IP_HEADER_LENGTH + UDP_PROTOCOL_LENGTH;
		ip_packet_hashing(ch, cp, ip_length, buf, SnmpData);
		break;
	default:
		/* So what do I do here ? */
		ip_length = IP_HEADER_LENGTH + 4;
		ip_packet_hashing(ch, cp, ip_length, buf, SnmpData);
	}
	return;
}

#ifdef INET6
void ipv6_print_hashing(const struct pcap_pkthdr32 *ch, u_char *cp, char *buf,
		SnmpTrapData * SnmpData) {
	register struct ip6_hdr *ip6_hdr;
	size_t ip_length;
	u_int8_t nxt; /* next_header */

	ip6_hdr = (struct ip6_hdr *) (cp + sizeof(struct ether_header));

	/* determine IP protocol */
	nxt = (u_int8_t) ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	switch (nxt) {
	case IPPROTO_TCP:
		ip_length = IP6_HEADER_LENGTH + TCP_PROTOCOL_LENGTH;
		ip_packet_hashing(ch, cp, ip_length, buf, SnmpData);
		break;
	case IPPROTO_UDP:
		ip_length = IP6_HEADER_LENGTH + UDP_PROTOCOL_LENGTH;
		ip_packet_hashing(ch, cp, ip_length, buf, SnmpData);
		break;
	default:
		/* So what do I do here ? */
		ip_length = IP6_HEADER_LENGTH;
		ip_packet_hashing(ch, cp, ip_length, buf, SnmpData);
	}
	return;
}
#endif

/*
 * Generate the hash depending on the hash function (hash_func)
 * {MD5 | SHA1 | RIPEMD160 }
 */

void make_hash_value(const int hash_func, u_char *data, unsigned long len,
		u_char *buf) {

	switch (hash_func) {
	case USE_MD5:
		MD5(data, len, buf);
		break;
	case USE_RIPEMD:
		RIPEMD160(data, len, buf);
		break;
	case USE_SHA1:
		SHA1(data, len, buf);
		break;
	default:
		;
	}
}

/*
 * adapted  from snmp_parse_args.c of net-snmp-5.0.5
 */

#ifdef HAVE_NETSNMP

#define BUF_SIZE 512
extern int snmpv3_options(char *optarg, netsnmp_session * session, char **Apsz,
		char **Xpsz, int argc, char * const *argv);

int snort_snmp_parse_args(int argc, char * const *argv,
		netsnmp_session * session, const char *localOpts, void(*proc)(int,
				char * const *, int)) {
	int arg;
	char *cp;
	char *Apsz = NULL;
	char *Xpsz = NULL;
	char *Cpsz = NULL;
	char Opts[BUF_SIZE];
	int tmpPort = 0;
	int nTmpPort = 0;
	char *peerName = NULL;
	int peerNameSize;
	char *lastColon = NULL;
	char *cPtr;
	char *tPtr;
	char aPortNo[16];
	int len;

	/*
	 * initialize session to default values
	 */
	snmp_sess_init(session);
	strncpy(Opts, "v:r:t:c:Z:e:E:n:u:l:x:X:a:A:p:T:-:3:s:", BUF_SIZE - 1);
	Opts[BUF_SIZE - 1] = 0;
	if (localOpts) {
		strncat(Opts, localOpts, BUF_SIZE - strlen(Opts) - 1);
		Opts[BUF_SIZE - 1] = 0;
	}
	/*
	 * get the options
	 */
	DEBUGMSGTL(("snmp_parse_args", "starting: %d/%d\n", optind, argc));
	for (arg = 0; arg < argc; arg++) {
		DEBUGMSGTL(("snmp_parse_args", " arg %d = %s\n", arg, argv[arg]));
	}

	optind = 1;
	while ((arg = getopt(argc, argv, Opts)) != EOF) {
		switch (arg) {
		case '-':
		case 'v':
			if (!strcmp(optarg, "1")) {
				session->version = SNMP_VERSION_1;
			} else if (!strcasecmp(optarg, "2c")) {
				session->version = SNMP_VERSION_2c;
			} else if (!strcasecmp(optarg, "3")) {
				session->version = SNMP_VERSION_3;
			} else {
				fprintf(stderr,
						"Invalid version specified after -v flag: %s\n", optarg);
				return (-1);
			}
			break;

		case 'p':
			tmpPort = atoi(optarg);
			if ((tmpPort < 1) || (tmpPort > 65535)) {
				fprintf(stderr, "Invalid port number after -p flag.\n");
				return (-1);
			}
			session->remote_port = (u_short) tmpPort;
			break;

		case 'T':
			fprintf(stderr, "Warning: -T option is no longer used - ");
			fprintf(stderr, "specify the remote host as TRANSPORT:HOST\n");
			return (-1);
			break;

		case 't':
			session->timeout = atoi(optarg) * 1000000L;
			if (session->timeout < 0 || !isdigit(optarg[0])) {
				fprintf(stderr, "Invalid timeout in seconds after -t flag.\n");
				return (-1);
			}
			break;

		case 'r':
			session->retries = atoi(optarg);
			if (session->retries < 0 || !isdigit(optarg[0])) {
				fprintf(stderr, "Invalid number of retries after -r flag.\n");
				return (-1);
			}
			break;

		case 'c':
			Cpsz = optarg;
			break;

		case '3':
			if (snmpv3_options(optarg, session, &Apsz, &Xpsz, argc, argv) < 0) {
				return (-1);
			}
			break;

		case 'Z':
			session->engineBoots = strtoul(optarg, NULL, 10);
			if (session->engineBoots == 0 || !isdigit(optarg[0])) {
				fprintf(stderr, "Need engine boots value after -Z flag.\n");
				return (-1);
			}
			cp = strchr(optarg, ',');
			if (cp && *(++cp) && isdigit(*cp))
				session->engineTime = strtoul(cp, NULL, 10);
			/*
			 * Handle previous '-Z boot time' syntax
			 */
			else if ((optind < argc) && isdigit(argv[optind][0]))
				session->engineTime = strtoul(argv[optind], NULL, 10);
			else {
				fprintf(stderr, "Need engine time value after -Z flag.\n");
				return (-1);
			}
			break;

		case 'e': {
			size_t ebuf_len = 32, eout_len = 0;
			u_char *ebuf = (u_char *) malloc(ebuf_len);

			if (ebuf == NULL) {
				fprintf(stderr, "malloc failure processing -e flag.\n");
				return (-1);
			}
			if (!snmp_hex_to_binary(&ebuf, &ebuf_len, &eout_len, 1, optarg)) {
				fprintf(stderr, "Bad engine ID value after -e flag.\n");
				free(ebuf);
				return (-1);
			}
			session->securityEngineID = ebuf;
			session->securityEngineIDLen = eout_len;
			break;
		}

		case 'E': {
			size_t ebuf_len = 32, eout_len = 0;
			u_char *ebuf = (u_char *) malloc(ebuf_len);

			if (ebuf == NULL) {
				fprintf(stderr, "malloc failure processing -E flag.\n");
				return (-1);
			}
			if (!snmp_hex_to_binary(&ebuf, &ebuf_len, &eout_len, 1, optarg)) {
				fprintf(stderr, "Bad engine ID value after -E flag.\n");
				free(ebuf);
				return (-1);
			}
			session->contextEngineID = ebuf;
			session->contextEngineIDLen = eout_len;
			break;
		}

		case 'n':
			session->contextName = optarg;
			session->contextNameLen = strlen(optarg);
			break;

		case 'u':
			session->securityName = optarg;
			session->securityNameLen = strlen(optarg);
			break;

		case 'l':
			if (!strcasecmp(optarg, "noAuthNoPriv") || !strcmp(optarg, "1")
					|| !strcasecmp(optarg, "nanp")) {
				session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
			} else if (!strcasecmp(optarg, "authNoPriv")
					|| !strcmp(optarg, "2") || !strcasecmp(optarg, "anp")) {
				session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
			} else if (!strcasecmp(optarg, "authPriv") || !strcmp(optarg, "3")
					|| !strcasecmp(optarg, "ap")) {
				session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
			} else {
				fprintf(stderr,
						"Invalid security level specified after -l flag: %s\n",
						optarg);
				return (-1);
			}

			break;

		case 'a':
			if (!strcasecmp(optarg, "MD5")) {
				session->securityAuthProto = usmHMACMD5AuthProtocol;
				session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
			} else if (!strcasecmp(optarg, "SHA")) {
				session->securityAuthProto = usmHMACSHA1AuthProtocol;
				session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
			} else {
				fprintf(
						stderr,
						"Invalid authentication protocol specified after -a flag: %s\n",
						optarg);
				return (-1);
			}
			break;

		case 'x':
			if (!strcasecmp(optarg, "DES")) {
				session->securityPrivProto = usmDESPrivProtocol;
				session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#ifdef HAVE_AES
			} else if (!strcasecmp(optarg, "AES128") || !strcasecmp(optarg,
					"AES")) {
				//                session->securityPrivProto = usmAESPrivProtocol;
				session->securityPrivProto = usmAES128PrivProtocol;
#endif
			} else {
				fprintf(
						stderr,
						"Invalid privacy protocol specified after -x flag: %s\n",
						optarg);
				return (-1);
			}
			break;

		case 'A':
			Apsz = optarg;
			break;

		case 'X':
			Xpsz = optarg;
			break;
		case 's':
			len = strlen(optarg);
			if ( len <= 0 ) {
				fprintf(stderr,
					"Invalid sensor address specified after -s flag: %s\n",
					optarg);
				return (-1);
			}
			sensorAddress = malloc(len+1);
			strncpy(sensorAddress, optarg, len+1);
			break;
		default:
			proc(argc, argv, arg);
			break;
		}
	}
	/* ErrorMessage("snmp_parse_args", "finished: %d/%d\n", optind, argc); */

	/*
	 * make master key from pass phrases
	 */
	if (Apsz) {
		session->securityAuthKeyLen = USM_AUTH_KU_LEN;
		if (session->securityAuthProto == NULL) {
			/*
			 * get .conf set default
			 */
			const oid *def = get_default_authtype(
					&session->securityAuthProtoLen);
			session->securityAuthProto = snmp_duplicate_objid(def,
					session->securityAuthProtoLen);
		}
		if (session->securityAuthProto == NULL) {
			/*
			 * assume MD5
			 */
			session->securityAuthProto = snmp_duplicate_objid(
					usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
			session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		}
		if (generate_Ku(session->securityAuthProto,
				session->securityAuthProtoLen, (u_char *) Apsz, strlen(Apsz),
				session->securityAuthKey, &session->securityAuthKeyLen)
				!= SNMPERR_SUCCESS) {
			snmp_perror(argv[0]);
			fprintf(stderr,
					"Error generating a key (Ku) from the supplied authentication pass phrase. \n");
			return (-2);
		}
	}
	if (Xpsz) {
		session->securityPrivKeyLen = USM_PRIV_KU_LEN;
		if (session->securityPrivProto == NULL) {
			/*
			 * get .conf set default
			 */
			const oid *def = get_default_privtype(
					&session->securityPrivProtoLen);
			session->securityPrivProto = snmp_duplicate_objid(def,
					session->securityPrivProtoLen);
		}
		if (session->securityPrivProto == NULL) {
			/*
			 * assume DES
			 */
			session->securityPrivProto = snmp_duplicate_objid(
					usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
			session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
		}
		if (generate_Ku(session->securityAuthProto,
				session->securityAuthProtoLen, (u_char *) Xpsz, strlen(Xpsz),
				session->securityPrivKey, &session->securityPrivKeyLen)
				!= SNMPERR_SUCCESS) {
			snmp_perror(argv[0]);
			fprintf(stderr,
					"Error generating a key (Ku) from the supplied privacy pass phrase. \n");
			return (-2);
		}
	}
	/*
	 * get the hostname
	 */
	if (optind == argc) {
		fprintf(stderr, "No hostname specified.\n");
		return (-1);
	}
	cPtr = argv[optind++]; /* hostname and perhaps the port number */
	if (cPtr) {
		if ((tPtr = strchr(cPtr, ']'))) {
			lastColon = strrchr(tPtr, ':');
		} else if ((tPtr = strchr(cPtr, ':')) && (strchr(++tPtr, ':'))) {
			/* just check if this is a v6 type address     */
			/* we cannot tell the prot number in this case */
		} else {
			lastColon = strrchr(cPtr, ':');

		}
		if (lastColon) /* we have got a port number - yei !! */
		{
			lastColon++;
			if (tmpPort) {
				ErrorMessage("Invalid port number after hostName\n");
				ErrorMessage("Port already specified after -p flag.\n");
				nTmpPort = atoi(lastColon);
				if (tmpPort != nTmpPort) {
					ErrorMessage("And they are different !! \n");
					return (-1);
				} else {
					ErrorMessage("But they are different !! \n");
					ErrorMessage("Will use both ........ !! \n");
				}
			} else /* if   (!tmpPort) */
			{
				tmpPort = atoi(lastColon);
				if ((tmpPort < 1) || (tmpPort > 65535)) {
					ErrorMessage("Invalid port number after hostName\n");
					return (-1);
				}
			}
#if 0
			*(lastColon -1) = 0; /* We will not need the ':portNumber' */
#endif
			peerName = cPtr;
		} else /* port number is not specified at the end of host name */
		{
			peerNameSize = strlen(cPtr) + 7;
			peerName = malloc(peerNameSize); /* space for host:port */
			if (peerName == NULL) {
				ErrorMessage("snort_snmp_parse_args: Malloc failed \n");
				FatalError("Quitting in snort_snmp_parse_args\n");
			}
			if (!tmpPort) {
				tmpPort = SNORT_DEFAULTSNMPTRAPD_PORT;
			}
			snprintf(aPortNo, sizeof(aPortNo), "%-6d", tmpPort);
			strncpy(peerName, cPtr, peerNameSize - 1);
			peerName[peerNameSize - 1] = 0;
			/* Will not need this if it is the 4.* ucd-snmp library */
#ifdef HAVE_NETSNMP    
			strncat(peerName, ":", peerNameSize - strlen(peerName) - 1);
			peerName[peerNameSize - 1] = 0;
			strncat(peerName, aPortNo, peerNameSize - strlen(peerName) - 1);
			peerName[peerNameSize - 1] = 0;
#endif
			session->remote_port = (u_short) tmpPort;
		}
		session->remote_port = (u_short) tmpPort;
		session->peername = peerName;
	}

	/*
	 * If v1 or v2c, check community has been set, either by a -c option above,
	 * or via a default token somewhere.
	 */

	if (session->version == SNMP_VERSION_1 || session->version
			== SNMP_VERSION_2c) {
		if (Cpsz == NULL) {
			Cpsz = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
					NETSNMP_DS_LIB_COMMUNITY);
		}
		if (Cpsz == NULL) {
			fprintf(stderr, "No community name specified.\n");
			return (-1);
		}
		session->community = (unsigned char *) Cpsz;
		session->community_len = strlen(Cpsz);
	}
	return optind;
}
#endif /* HAVE_NETSNMP */
#endif
