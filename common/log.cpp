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
#include <iostream>
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

// ----- Logger driver specific HLO commands -----

// Open log file if closed
#define LOCAL_HLO_CMD_LOG_OPEN HLO_OP_USER_DEFINED

// Close log file
#define LOCAL_HLO_CMD_LOG_CLOSE HLO_OP_USER_DEFINED + 1

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
    memset(m_key, 0, 16); // Clear encryption key

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

            if (0 == strcmp(attr[i], "debug")) {
                if (!attribute.empty()) {
                    if (0 == vscp_strcasecmp(attribute.c_str(), "TRUE")) {
                        pLog->m_bDebug = true;
                    } else {
                        pLog->m_bDebug = false;
                    }
                    if (pLog->m_bDebug) {
                        syslog(LOG_DEBUG,
                               "[vscpl2drv-logger] 'bDebug' set to true.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "access")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if (std::string::npos != attribute.find("W")) {
                        pLog->m_bWrite = true;
                    } else {
                        pLog->m_bWrite = false;
                    }
                    if (std::string::npos != attribute.find("R")) {
                        pLog->m_bRead = true;
                    } else {
                        pLog->m_bRead = false;
                    }
                }
            } else if (0 == strcmp(attr[i], "path-config")) {
                if (!attribute.empty()) {
                    pLog->m_pathLogfile = attribute;
                }
                if (pLog->m_bDebug) {
                    syslog(LOG_DEBUG,
                           "[vscpl2drv-logger] Log file path set to [%s].",
                           pLog->m_pathLogfile.c_str());
                }
            } else if (0 == strcmp(attr[i], "filter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pLog->m_vscpfilterTx,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-logger] Unable to read event "
                               "receive filter.");
                    } else if (pLog->m_bDebug) {
                        std::string str;
                        vscp_writeFilterToString(str, &pLog->m_vscpfilterTx);
                        syslog(
                          LOG_DEBUG,
                          "[vscpl2drv-logger] Tx filter set to set to [%s].",
                          str.c_str());
                    }
                }
            } else if (0 == strcmp(attr[i], "mask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pLog->m_vscpfilterTx,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-logger] Unable to read event "
                               "receive mask.");
                    } else if (pLog->m_bDebug) {
                        std::string str;
                        vscp_writeMaskToString(str, &pLog->m_vscpfilterTx);
                        syslog(LOG_DEBUG,
                               "[vscpl2drv-logger] Tx mask set to set to [%s].",
                               str.c_str());
                    }
                }
            } else if (0 == strcmp(attr[i], "overwrite")) {
                if (!attribute.empty()) {
                    if (0 == vscp_strcasecmp(attribute.c_str(), "TRUE")) {
                        pLog->m_bOverWrite = true;
                    } else {
                        pLog->m_bOverWrite = false;
                    }
                    if (pLog->m_bDebug) {
                        syslog(LOG_DEBUG,
                               "[vscpl2drv-logger] 'boverwrite' set to %s].",
                               pLog->m_bOverWrite ? "true" : "false");
                    }
                }
            } else if (0 == strcmp(attr[i], "worksfmt")) {
                if (!attribute.empty()) {
                    if (0 == vscp_strcasecmp(attribute.c_str(), "TRUE")) {
                        pLog->m_bWorksFmt = true;
                    } else {
                        pLog->m_bWorksFmt = false;
                    }
                    if (pLog->m_bDebug) {
                        syslog(LOG_DEBUG,
                               "[vscpl2drv-logger] 'bworksfmt' set to %s].",
                               pLog->m_bWorksFmt ? "true" : "false");
                    }
                }
            } else if (0 == strcmp(attr[i], "path-key")) {
                size_t n;
                if (!attribute.empty()) {
                    pLog->m_pathKey = attribute;
                    if (0 == (n = pLog->readEncryptionKey())) {
                        syslog(LOG_INFO,
                               "[vscpl2drv-logger] Could not read encryption "
                               "key. Will not use encryption.");
                    } else {
                        if (pLog->m_bDebug) {
                            syslog(
                              LOG_DEBUG,
                              "[vscpl2drv-logger] Encryption key read from "
                              "[%s] length: %zu.",
                              pLog->m_pathKey.c_str(),
                              n);
                        }
                    }
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

    // Not allowed to have append and VSCP Works format
    if (m_bWorksFmt && !m_bOverWrite) {
        m_bOverWrite = true;
        syslog(LOG_ERR,
               "[vscpl2drv-logger] VSCP Works format require that "
               "overwrite=\"true\". Now forced to true.");
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
    std::string access;
    std::string filter;
    std::string mask;

    if (m_bRead) {
        access = "r";
    }

    if (m_bWrite) {
        access = "w";
    }

    vscp_writeFilterToString(filter, &m_vscpfilterTx);
    vscp_writeMaskToString(mask, &m_vscpfilterTx);

    std::string cfg = vscp_str_format(TEMPLATE_LOGGER_CONF_FILE,
                                      (m_bDebug ? "true" : "false"),
                                      access.c_str(),
                                      m_pathKey.c_str(),
                                      m_pathConfig.c_str(),
                                      (m_bOverWrite ? "true" : "false"),
                                      (m_bWorksFmt ? "true" : "false"),
                                      filter.c_str(),
                                      mask.c_str());

    try {
    std::ofstream fs;
    fs.open (m_pathConfig);
    fs << cfg;
    fs.close();
    } catch (...) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to save configuration file.");    
        return false;
    }

    return true;
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void* data, const char* name, const char** attr)
{
    CHLO* pObj = (CHLO*)data;
    if (NULL == pObj) {
        return;
    }

    if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "op")) {
                if (!attribute.empty()) {
                    pObj->m_op = vscp_readStringValue(attribute);
                    vscp_makeUpper(attribute);
                    if (pObj->m_bDebug) {
                        syslog(LOG_DEBUG,
                               "[vscpl2drv-logger] <vscp-cmd op=\"%s\" ",
                               attribute.c_str());
                    }
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
    uint8_t outbuf[VSCP_MAX_DATA];

    // GUID + type = 17 + dummy payload size=1
    if (size < 18) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: HLO buffer size is wring.");
        return false;
    }

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

    // Decrypt if needed
    if (vscp_fileExists(m_pathKey)) {
        vscp_decryptFrame(outbuf,
                          inbuf + 16,
                          size - 16,
                          m_key,
                          NULL,
                          VSCP_ENCRYPTION_AES256);
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
    hlo.m_bDebug = m_bDebug;
    if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to parse HLO.");
        return false;
    }

    ex.obid      = 0;
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_HLO;
    ex.vscp_type  = VSCP2_TYPE_HLO_RESPONSE;
    m_guid.writeGUID(ex.GUID);

    switch (hlo.m_op) {

        case HLO_OP_NOOP:
            // Send positive response
            sprintf(buf,
                    HLO_CMD_REPLY_TEMPLATE,
                    "noop",
                    "OK",
                    "NOOP commaned executed correctly.");

            break;

        case HLO_OP_READ_VAR:
            if (m_bRead) {
                if ("DEBUG" == hlo.m_name) {
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "debug",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                            vscp_convertToBase64(m_bDebug ? "true" : "false")
                              .c_str());
                } else if ("OVERWRITE" == hlo.m_name) {
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "overwrite",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                            vscp_convertToBase64(m_bDebug ? "true" : "false")
                              .c_str());
                } else if ("WORKSFMT" == hlo.m_name) {
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "worksfmt",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                            vscp_convertToBase64(m_bDebug ? "true" : "false")
                              .c_str());
                } else if ("PATH-CONFIG" == hlo.m_name) {
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "path-config",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_pathConfig.c_str()).c_str());
                } else if ("FILTER" == hlo.m_name) {
                    std::string str, filter;
                    vscp_writeFilterToString(filter, &m_vscpfilterTx);
                    vscp_writeMaskToString(str, &m_vscpfilterTx);
                    filter += str;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "filter",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_FILTER,
                            vscp_convertToBase64(filter.c_str()).c_str());
                } else {
                    sprintf(
                      buf,
                      HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                      hlo.m_name.c_str(),
                      ERR_VARIABLE_UNKNOWN,
                      vscp_convertToBase64(std::string("Unknown variable"))
                        .c_str());
                }
            } else {
                // Reads not allowed
                sprintf(
                      buf,
                      HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                      hlo.m_name.c_str(),
                      ERR_VARIABLE_PERMISSION,
                      vscp_convertToBase64(std::string("Not allowed to read variable"))
                        .c_str());
            }
            break;

        case HLO_OP_WRITE_VAR:
            if (m_bWrite) {
                if ("DEBUG" == hlo.m_name) {
                    std::string str = hlo.m_value;
                    vscp_makeUpper(str);
                    if (std::string::npos != str.find("TRUE")) {
                        m_bDebug = true;
                        sprintf(
                          buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "debug",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                          vscp_convertToBase64(m_bDebug ? "true" : "false")
                            .c_str());
                    } else if (std::string::npos != str.find("FALSE")) {
                        m_bDebug = false;
                        sprintf(
                          buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "debug",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                          vscp_convertToBase64(m_bDebug ? "true" : "false")
                            .c_str());
                    } else {
                        // Invalid value
                        sprintf(buf,
                                HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                                "debug",
                                ERR_VARIABLE_VALUE,
                                vscp_convertToBase64("Invalid value").c_str());
                    }
                } else if ("OVERWRITE" == hlo.m_name) {

                    std::string str = hlo.m_value;
                    vscp_makeUpper(str);
                    if (std::string::npos != str.find("TRUE")) {
                        m_bOverWrite = true;
                        sprintf(
                          buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "overwrite",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                          vscp_convertToBase64(m_bOverWrite ? "true" : "false")
                            .c_str());
                    } else if (std::string::npos != str.find("FALSE")) {
                        m_bOverWrite = false;
                        sprintf(
                          buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "overwrite",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                          vscp_convertToBase64(m_bOverWrite ? "true" : "false")
                            .c_str());
                    } else {
                        // Invalid value
                        sprintf(buf,
                                HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                                "overwrite",
                                ERR_VARIABLE_VALUE,
                                vscp_convertToBase64("Invalid value").c_str());
                    }
                } else if ("WORKSFMT" == hlo.m_name) {
                    std::string str = hlo.m_value;
                    vscp_makeUpper(str);
                    if (std::string::npos != str.find("TRUE")) {
                        m_bWorksFmt = true;
                        sprintf(
                          buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "worksfmt",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                          vscp_convertToBase64(m_bWorksFmt ? "true" : "false")
                            .c_str());
                    } else if (std::string::npos != str.find("FALSE")) {
                        m_bWorksFmt = false;
                        sprintf(
                          buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "worksfmt",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                          vscp_convertToBase64(m_bWorksFmt ? "true" : "false")
                            .c_str());
                    } else {
                        // Invalid value
                        sprintf(buf,
                                HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                                "overwrite",
                                ERR_VARIABLE_VALUE,
                                vscp_convertToBase64("Invalid value").c_str());
                    }
                } else if ("PATH-CONFIG" == hlo.m_name) {
                    if (VSCP_REMOTE_VARIABLE_CODE_STRING == hlo.m_varType) {
                        if (vscp_fileExists(hlo.m_value)) {
                            m_pathConfig = hlo.m_value;
                            sprintf(buf,
                                    HLO_READ_VAR_REPLY_TEMPLATE,
                                    "path-config",
                                    "OK",
                                    VSCP_REMOTE_VARIABLE_CODE_STRING,
                                    vscp_convertToBase64(m_pathConfig.c_str())
                                      .c_str());
                        } else {
                            sprintf(buf,
                                    HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                                    "path-config",
                                    VSCP_ERROR_WRITE_ERROR,
                                    vscp_convertToBase64(
                                      "Invalid path (existence/permissions)")
                                      .c_str());
                        }
                    } else {
                        // Error
                        sprintf(buf,
                                HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                                "path-config",
                                ERR_VARIABLE_WRONG_TYPE,
                                vscp_convertToBase64(
                                  "Invalid variable type -  Should be string")
                                  .c_str());
                    }
                } else if ("FILTER" == hlo.m_name) {
                    if (VSCP_REMOTE_VARIABLE_CODE_FILTER == hlo.m_varType) {
                        if (vscp_readFilterMaskFromString(&m_vscpfilterTx,
                                                          hlo.m_value)) {
                            std::string str, filter;
                            vscp_writeFilterToString(filter, &m_vscpfilterTx);
                            vscp_writeMaskToString(str, &m_vscpfilterTx);
                            filter += str;
                            sprintf(
                              buf,
                              HLO_READ_VAR_REPLY_TEMPLATE,
                              "filter",
                              "OK",
                              VSCP_REMOTE_VARIABLE_CODE_FILTER,
                              vscp_convertToBase64(filter.c_str()).c_str());
                        } else {
                            sprintf(
                              buf,
                              HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                              "filter",
                              VSCP_ERROR_WRITE_ERROR,
                              vscp_convertToBase64("Invalid filter").c_str());
                        }
                    } else {
                        // Error
                        sprintf(buf,
                                HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                                "filter",
                                ERR_VARIABLE_WRONG_TYPE,
                                vscp_convertToBase64(
                                  "Invalid variable type -  Should be filter")
                                  .c_str());
                    }
                } else {
                    sprintf(
                      buf,
                      HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                      hlo.m_name.c_str(),
                      ERR_VARIABLE_UNKNOWN,
                      vscp_convertToBase64(std::string("Unknown variable"))
                        .c_str());
                }
            } else {
                // Writes not allowed
                sprintf(
                      buf,
                      HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                      hlo.m_name.c_str(),
                      ERR_VARIABLE_READ_ONLY,
                      vscp_convertToBase64(std::string("Not allowed to write variable"))
                        .c_str());
            }
            break;

        case HLO_OP_SAVE:
            if (m_bDebug) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] HLO_OP_SAVE - Saving "
                       "configuration.");
            }
            doSaveConfig();
            break;

        case HLO_OP_LOAD:
            syslog(LOG_ERR,
                   "[vscpl2drv-logger] HLO_OP_LOAD - Loading "
                   "configuration.");
            doLoadConfig();
            break;

        case LOCAL_HLO_CMD_LOG_OPEN:
            if (m_bDebug) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] HLO-CMD OPEN - Opening logfile "
                       "[%s][%s] .",
                       m_pathLogfile.c_str(),
                       (m_logStream.is_open() ? "open" : "closed"));

                if (!m_logStream.is_open()) {
                    if (!openLogFile()) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-logger] HLO-CMD OPEN - Failed to "
                               "open logfile [%s].",
                               m_pathLogfile.c_str());
                    }
                }
                break;

                case LOCAL_HLO_CMD_LOG_CLOSE:
                    if (m_bDebug) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-logger] HLO-CMD CLOSE - Closing "
                               "logfile [%s][%s] .",
                               m_pathLogfile.c_str(),
                               (m_logStream.is_open() ? "open" : "closed"));
                    }
                    if (m_logStream.is_open()) {
                        m_logStream.close();
                    }
                    break;

                default:
                    // This command is not understood
                    sprintf(
                      buf,
                      HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                      hlo.m_name.c_str(),
                      ERR_VARIABLE_UNKNOWN,
                      vscp_convertToBase64(std::string("Unknown variable"))
                        .c_str());
                    break;
            };
    }

    memset(ex.data, 0, sizeof(ex.data));
    ex.sizeData = strlen(buf);
    memcpy(ex.data, buf, ex.sizeData);

    // Put event in receive queue
    return eventExToReceiveQueue(ex);
}

///////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

size_t
CVSCPLog::readEncryptionKey(void)
{
    size_t keySize = 0;
    std::string line;
    if (m_pathKey.size()) {
        std::string line;
        std::ifstream keyfile(m_pathKey);
        if (keyfile.is_open()) {
            getline(keyfile, line);
            vscp_trim(line);
            keySize = vscp_hexStr2ByteArray(m_key, 32, line.c_str());
            keyfile.close();
        } else {
            syslog(LOG_ERR, "[vscpl2drv-logger] Failed to get encryption key.");
        }
    }

    return keySize;
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
CVSCPLog::openLogFile(void)
{
    try {
        if (m_bOverWrite) {

            m_logStream.open(m_pathLogfile, std::ios::out | std::ios::trunc);
            if (!m_logStream.is_open()) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] Failed to open log file [%s].",
                       m_pathLogfile.c_str());
                return false;
            }

            if (m_bDebug) {
                syslog(LOG_DEBUG,
                       "Successfully opened logfile [%s]",
                       m_pathLogfile.c_str());
            }

            // Write XML start data
            if (m_bWorksFmt) {
                m_logStream
                  << "<?xml version = \"1.0\" encoding = \"UTF-8\" ?>\n";
                // RX data start
                m_logStream << "<vscprxdata>\n";
                m_logStream.flush();
                return true;
            }

        } else {

            m_logStream.open(m_pathLogfile, std::ios::out | std::ios::app);
            if (!m_logStream.is_open()) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] Failed to open log file [%s].",
                       m_pathLogfile.c_str());
                return false;
            }

            if (m_bDebug) {
                syslog(LOG_DEBUG,
                       "Successfully opened logfile [%s]",
                       m_pathLogfile.c_str());
            }
        }
    } catch (...) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to open log file!");
        return false;
    }

    return false;
}

//////////////////////////////////////////////////////////////////////
// writeEvent2Log
//

bool
CVSCPLog::writeEvent2Log(vscpEvent* pEvent)
{
    if (m_logStream.is_open()) {
        if (m_bWorksFmt) {

            std::string str;

            // * * * VSCP Works log format * * *

            // Event
            m_logStream << "<event>\n";
            m_logStream << "<dir>\n";
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

            m_logStream.flush();

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

            m_logStream.flush();
        }
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
        syslog(LOG_ERR,
               "[vscpl2drv-logger] No thread object supplied to worker thread. "
               "Aborting!");
        return NULL;
    }

    // Check pointers
    if (NULL == pObj->m_pLog) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] No valid logger object suppied to worker "
               "thread. Aborting!");
        return NULL;
    }

    // Open the file
    if (!pObj->m_pLog->openLogFile()) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to open log file. Aborting");
        return NULL;
    }

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

            if (NULL == pEvent) {
                continue;
            }

            // Only HLO object event is of interst to us
            if ((VSCP_CLASS2_HLO == pEvent->vscp_class) &&
                (VSCP2_TYPE_HLO_COMMAND == pEvent->vscp_type) &&
                vscp_isSameGUID(pObj->m_pLog->m_guid.getGUID(), pEvent->GUID)) {
                pObj->m_pLog->handleHLO(pEvent);
                // Fall through and log event...
            }

            pObj->m_pLog->writeEvent2Log(pEvent);

            vscp_deleteEvent(pEvent);
            pEvent = NULL;

        } // Event received

    } // Receive loop

    // Close the channel
    pObj->m_srv.doCmdClose();

    return NULL;
}
