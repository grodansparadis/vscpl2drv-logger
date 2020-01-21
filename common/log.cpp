// Log.cpp: implementation of the CVSCPLog class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2020 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include <deque>
#include <fstream>
#include <list>
#include <string>

#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <expat.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include "log.h"

// Buffer size for XML parser
#define XML_BUFF_SIZE 10000

// Forward declarations
void*
threadWorker(void* pData);

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
// CVSCPLog
//

CVSCPLog::CVSCPLog()
{
    m_bQuit      = false;
    m_bRead      = false;
    m_bWrite     = false;
    m_bQuit      = false;
    m_bOverWrite = false;
    m_bWorksFmt  = true;
    memset(m_Key, 0, 16); // Clear encryption key

    vscp_clearVSCPFilter(&m_vscpfilterTx); // Accept all TX events

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);
}

//////////////////////////////////////////////////////////////////////
// ~CVSCPLog
//

CVSCPLog::~CVSCPLog()
{

    close();

    pthread_mutex_destroy(&m_mutexSendQueue);
    pthread_mutex_destroy(&m_mutexReceiveQueue);

    sem_destroy(&m_semSendQueue);
    sem_destroy(&m_semReceiveQueue);
}

// ----------------------------------------------------------------------------

/* clang-format off */

// ----------------------------------------------------------------------------

/*
    XML Setup
    ==========
    <setup debug="true|false"
            access="rw"
            path-key="Path to 256-bit crypto key"
            path="path-to-log-file"
            brewrite="true|false"
            bworksfmt="true|false"
            filter="VSCP filter on string format"
            mask="VSCP mask on string format" />
*/

/* clang-format on */

// ----------------------------------------------------------------------------

int depth_setup_parser = 0;

void
startSetupParser(void* data, const char* name, const char** attr)
{
    CVSCPLog* pLog = (CVSCPLog*)data;
    if (NULL == pLog)
        return;

    if ((0 == strcmp(name, "setup")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcmp(attr[i], "path")) {
                if (!attribute.empty()) {
                    pLog->m_pathLogfile = attribute;
                }
            } else if (0 == strcmp(attr[i], "filter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pLog->m_vscpfilterTx,
                                                   attribute)) {
                        syslog(LOG_ERR, "Unable to read event receive filter.");
                    }
                }
            } else if (0 == strcmp(attr[i], "mask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pLog->m_vscpfilterTx,
                                                 attribute)) {
                        syslog(LOG_ERR, "Unable to read event receive mask.");
                    }
                }
            } else if (0 == strcmp(attr[i], "brewrite")) {
                if (!attribute.empty()) {
                    if (0 == vscp_strcasecmp(attribute.c_str(), "TRUE")) {
                        pLog->m_bOverWrite = true;
                    } else {
                        pLog->m_bOverWrite = false;
                    }
                }
            } else if (0 == strcmp(attr[i], "bworksfmt")) {
                if (!attribute.empty()) {
                    if (0 == vscp_strcasecmp(attribute.c_str(), "TRUE")) {
                        pLog->m_bWorksFmt = true;
                    } else {
                        pLog->m_bWorksFmt = false;
                    }
                }
            } else if (0 == strcmp(attr[i], "path-key")) {
                if (!attribute.empty()) {
                    pLog->m_pathKey = attribute;
                }
            }
        }
    }

    depth_setup_parser++;
}

void
endSetupParser(void* data, const char* name)
{
    depth_setup_parser--;
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// open
//

bool
CVSCPLog::open(std::string& pathcfg, cguid& guid)
{
    // Set GUID
    m_guid = guid;

    // Save config path
    m_pathConfig = pathcfg;

    // Read configuration file
    if (!doLoadConfig()) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] Failed to load configuration file [%s]",
               m_pathConfig.c_str());
    }

    // start the worker thread
    m_pWorkObj = new CLogWrkThreadObj();
    if (NULL != m_pWorkObj) {

        m_pWorkObj->m_pLog = this;

        if (pthread_create(&m_pWrkThread, NULL, threadWorker, m_pWorkObj)) {
            syslog(LOG_CRIT, "Unable to start logger driver worker thread.");
            return false;
        }
    } else {
        syslog(LOG_CRIT, "Unable to allocate thread object.");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CVSCPLog::close(void)
{
    if (m_logStream.is_open() && m_bWorksFmt) {
        m_logStream.write("</vscprxdata>\n", strlen("</vscprxdata>\n"));
    }

    // Close the log-file
    m_logStream.close();

    // Do nothing if already terminated
    if (m_bQuit)
        return;

    m_bQuit = true; // terminate the thread
    sleep(1);       // Give the thread some time to terminate
}

//////////////////////////////////////////////////////////////////////
// doFilter
//

bool
CVSCPLog::doFilter(vscpEvent* pEvent)
{
    return true;
}

//////////////////////////////////////////////////////////////////////
// setFilter
//

void
CVSCPLog::setFilter(vscpEvent* pFilter)
{
    return;
}

//////////////////////////////////////////////////////////////////////
// setMask
//

void
CVSCPLog::setMask(vscpEvent* pMask)
{
    return;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
CVSCPLog::doLoadConfig(void)
{
    FILE* fp;

    fp = fopen(m_pathConfig.c_str(), "r");
    if (NULL == fp) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] Failed to open configuration file [%s]",
               m_pathConfig.c_str());
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startSetupParser, endSetupParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    size_t file_size = 0;
    file_size        = fread(buf, sizeof(char), XML_BUFF_SIZE, fp);
    fclose(fp);

    if (XML_STATUS_OK !=
        XML_ParseBuffer(xmlParser, file_size, file_size == 0)) {
        enum XML_Error errcode = XML_GetErrorCode(xmlParser);
        syslog(LOG_ERR,
               "[vscpl2drv-logger] Failed parse XML setup [%s].",
               XML_ErrorString(errcode));
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CVSCPLog::doSaveConfig(void)
{
    return true;
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void* data, const char* name, const char** attr)
{
    CHLO* pObj = (CHLO*)data;
    if (NULL == pObj)
        return;

    if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "op")) {
                if (!attribute.empty()) {
                    pObj->m_op = vscp_readStringValue(attribute);
                    vscp_makeUpper(attribute);
                    if (attribute == "VSCP-NOOP") {
                        pObj->m_op = HLO_OP_NOOP;
                    } else if (attribute == "VSCP-READVAR") {
                        pObj->m_op = HLO_OP_READ_VAR;
                    } else if (attribute == "VSCP-WRITEVAR") {
                        pObj->m_op = HLO_OP_WRITE_VAR;
                    } else if (attribute == "VSCP-LOAD") {
                        pObj->m_op = HLO_OP_LOAD;
                    } else if (attribute == "VSCP-SAVE") {
                        pObj->m_op = HLO_OP_SAVE;
                    } else {
                        pObj->m_op = HLO_OP_UNKNOWN;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "name")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    pObj->m_name = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "type")) {
                if (!attribute.empty()) {
                    pObj->m_varType = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "value")) {
                if (!attribute.empty()) {
                    if (vscp_base64_std_decode(attribute)) {
                        pObj->m_value = attribute;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "full")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if ("TRUE" == attribute) {
                        pObj->m_bFull = true;
                    } else {
                        pObj->m_bFull = false;
                    }
                }
            }
        }
    }

    depth_hlo_parser++;
}

void
endHLOParser(void* data, const char* name)
{
    depth_hlo_parser--;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

bool
CVSCPLog::parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo)
{
    // Check pointers
    if (NULL == inbuf) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: HLO in-buffer pointer is NULL.");
        return false;
    }

    if (NULL == phlo) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: HLO obj pointer is NULL.");
        return false;
    }

    if (!size) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: HLO buffer size is zero.");
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    // Copy in the HLO object
    memcpy(buf, inbuf, size);

    if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed parse XML setup.");
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CVSCPLog::handleHLO(vscpEvent* pEvent)
{
    char buf[512]; // Working buffer
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent) {
        syslog(LOG_ERR, "[vscpl2drv-logger] HLO handler: NULL event pointer.");
        return false;
    }

    CHLO hlo;
    if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to parse HLO.");
        return false;
    }

    ex.obid      = 0;
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_HLO;
    ex.vscp_type  = VSCP2_TYPE_HLO_COMMAND;
    m_guid.writeGUID(ex.GUID);

    switch (hlo.m_op) {

        case HLO_OP_NOOP:
            // Send positive response
            sprintf(buf,
                    HLO_CMD_REPLY_TEMPLATE,
                    "noop",
                    "OK",
                    "NOOP commaned executed correctly.");

            memset(ex.data, 0, sizeof(ex.data));
            ex.sizeData = strlen(buf);
            memcpy(ex.data, buf, ex.sizeData);

            // Put event in receive queue
            return eventExToReceiveQueue(ex);

        case HLO_OP_READ_VAR:
            if ("DEBUG" == hlo.m_name) {
                /*sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "sunrise",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_DATETIME,
                        vscp_convertToBase64(getSunriseTime().getISODateTime())
                          .c_str());*/
            } else if ("PATH" == hlo.m_name) {
                /*sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "sunrise",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_DATETIME,
                        vscp_convertToBase64(getSunriseTime().getISODateTime())
                          .c_str());*/
            } else if ("OVERWRITE" == hlo.m_name) {
                /*sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "sunrise",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_DATETIME,
                        vscp_convertToBase64(getSunriseTime().getISODateTime())
                          .c_str());*/
            } else if ("WORKSFMT" == hlo.m_name) {
                /*sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "sunrise",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_DATETIME,
                        vscp_convertToBase64(getSunriseTime().getISODateTime())
                          .c_str());*/
            } else {
                sprintf(buf,
                        HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                        hlo.m_name.c_str(),
                        ERR_VARIABLE_UNKNOWN,
                        vscp_convertToBase64(std::string("Unknown variable"))
                          .c_str());
            }
            break;

        case HLO_OP_WRITE_VAR:
            if ("SUNRISE" == hlo.m_name) {
                // Read Only variable
                sprintf(buf,
                        HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                        "sunrise",
                        VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                        "Variable is read only.");
            } else {
                sprintf(buf,
                        HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                        hlo.m_name.c_str(),
                        1,
                        vscp_convertToBase64(std::string("Unknown variable"))
                          .c_str());
            }
            break;

        case HLO_OP_SAVE:
            doSaveConfig();
            break;

        case HLO_OP_LOAD:
            doLoadConfig();
            break;

        default:
            break;
    };

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CVSCPLog::readEncryptionKey(void)
{
    std::string line;
    if (m_pathKey.size()) {
        std::string line;
        std::ifstream keyfile(m_pathKey);
        if (keyfile.is_open()) {
            getline(keyfile, line);
            vscp_hexStr2ByteArray(m_Key, 16, line.c_str());
            keyfile.close();
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CVSCPLog::eventExToReceiveQueue(vscpEventEx& ex)
{
    vscpEvent* pev = new vscpEvent();
    if (!vscp_convertEventExToEvent(pev, &ex)) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] Failed to convert event from ex to ev.");
        vscp_deleteEvent(pev);
        return false;
    }
    if (NULL != pev) {
        pthread_mutex_lock(&m_mutexReceiveQueue);
        m_receiveList.push_back(pev);
        sem_post(&m_semReceiveQueue);
        pthread_mutex_unlock(&m_mutexReceiveQueue);
    } else {
        syslog(LOG_ERR, "[vscpl2drv-logger] Unable to allocate event storage.");
    }
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
CVSCPLog::addEvent2SendQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexSendQueue);
    m_sendList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semSendQueue);
    pthread_mutex_unlock(&m_mutexSendQueue);
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//

bool
CVSCPLog::addEvent2ReceiveQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexReceiveQueue);
    m_receiveList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semReceiveQueue);
    pthread_mutex_unlock(&m_mutexReceiveQueue);
    return true;
}

//////////////////////////////////////////////////////////////////////
// openFile
//

bool
CVSCPLog::openFile(void)
{
    try {
        if (m_bOverWrite) {

            m_logStream.open(m_pathLogfile, std::fstream::out);

            if (m_bWorksFmt) {
                m_logStream
                  << "<?xml version = \"1.0\" encoding = \"UTF-8\" ?>\n";
                // RX data start
                m_logStream << "<vscprxdata>\n";
                return true;
            } else {
                return true;
            }

        } else {

            m_logStream.open(m_pathLogfile, std::fstream::out);

            if (m_bWorksFmt) {
                m_logStream
                  << "<?xml version = \"1.0\" encoding = \"UTF-8\" ?>\n";
                // RX data start
                m_logStream << "<vscprxdata>\n";
                return true;
            } else {
                return true;
            }
        }
    } catch (...) {
        syslog(LOG_CRIT, "Failed to open log file!");
        return false;
    }

    return false;
}

//////////////////////////////////////////////////////////////////////
// writeEvent
//

bool
CVSCPLog::writeEvent(vscpEvent* pEvent)
{

    if (m_bWorksFmt) {

        std::string str;

        // * * * VSCP Works log format * * *

        // Event
        m_logStream << "<event>\n";
        m_logStream << "rx";
        m_logStream << "</dir>\n";

        m_logStream << "<time>";
        str = vscpdatetime::Now().getISODateTime();
        m_logStream << str.c_str();
        m_logStream << "</time>\n";

        m_logStream << "<dt>";
        if (!vscp_getDateStringFromEvent(str, pEvent)) {
            str = "Failed to get date/time.";
        }
        m_logStream << str.c_str();
        m_logStream << "</dt>\n";

        m_logStream << "<head>" << pEvent->head;
        m_logStream << "</head>\n";

        m_logStream << "<class>";
        m_logStream << pEvent->vscp_class;
        m_logStream << "</class>\n";

        m_logStream << "<type>";
        m_logStream << pEvent->vscp_type;
        m_logStream << "</type>\n";

        m_logStream << "<guid>";
        vscp_writeGuidToString(str, pEvent);
        m_logStream << str.c_str();
        m_logStream << "</guid>\n";

        m_logStream << "<sizedata>"; // Not used by read routine
        m_logStream << pEvent->sizeData;
        m_logStream << "</sizedata>\n";

        if (0 != pEvent->sizeData) {
            m_logStream << "<data>";
            vscp_writeDataToString(str, pEvent);
            m_logStream << str.c_str();
            m_logStream << "</data>\n";
        }

        m_logStream << "<timestamp>";
        m_logStream << pEvent->timestamp;
        m_logStream << "</timestamp>\n";

        m_logStream << "<note>";
        m_logStream << "</note>\n";

        m_logStream << "</event>\n";

    } else {

        // * * * Standard log format * * *
        std::string str;

        str = vscpdatetime::Now().getISODateTime();
        m_logStream << str.c_str();

        str = vscp_str_format("head=%d ", pEvent->head);
        m_logStream << str.c_str();

        str = vscp_str_format("class=%d ", pEvent->vscp_class);
        m_logStream << str.c_str();

        str = vscp_str_format("type=%d ", pEvent->vscp_type);
        m_logStream << str.c_str();

        str = vscp_str_format("GUID=", pEvent->vscp_type);
        m_logStream << str.c_str();

        vscp_writeGuidToString(str, pEvent);
        m_logStream << str.c_str();

        str = vscp_str_format(" datasize=%d ", pEvent->sizeData);
        m_logStream << str.c_str();

        if (0 != pEvent->sizeData) {
            str = vscp_str_format("data=", pEvent->vscp_type);
            m_logStream << str.c_str();
            vscp_writeDataToString(str, pEvent);
            m_logStream << str.c_str();
        }

        str = vscp_str_format(" Timestamp=%d\r\n", pEvent->timestamp);
        m_logStream << str.c_str();
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
//                           Workerthread
//////////////////////////////////////////////////////////////////////

CLogWrkThreadObj::CLogWrkThreadObj()
{
    m_pLog = NULL;
}

CLogWrkThreadObj::~CLogWrkThreadObj() {}

///////////////////////////////////////////////////////////////////////////////
// 								Worker thread
///////////////////////////////////////////////////////////////////////////////

void*
threadWorker(void* pData)
{
    CLogWrkThreadObj* pObj = (CLogWrkThreadObj*)pData;
    if (NULL == pObj) {
        syslog(LOG_CRIT,
               "No thread object supplied to worker thread. Aborting!");
        return NULL;
    }

    // Check pointers
    if (NULL == pObj->m_pLog) {
        syslog(LOG_CRIT,
               "No valid logger object suppied to worker thread. Aborting!");
        return NULL;
    }

    // Open the file
    if (!pObj->m_pLog->openFile())
        return NULL;

    while (!pObj->m_pLog->m_bQuit) {

        // Wait for events
        if ((-1 == vscp_sem_wait(&pObj->m_pLog->m_semSendQueue, 500)) &&
            errno == ETIMEDOUT) {
            continue;
        }

        if (pObj->m_pLog->m_sendList.size()) {

            pthread_mutex_lock(&pObj->m_pLog->m_mutexSendQueue);
            vscpEvent* pEvent = pObj->m_pLog->m_sendList.front();
            pObj->m_pLog->m_sendList.pop_front();
            pthread_mutex_unlock(&pObj->m_pLog->m_mutexSendQueue);

            if (NULL == pEvent)
                continue;
            pObj->m_pLog->writeEvent(pEvent);
            vscp_deleteEvent(pEvent);
            pEvent = NULL;

        } // Event received

    } // Receive loop

    // Close the channel
    pObj->m_srv.doCmdClose();

    return NULL;
}
