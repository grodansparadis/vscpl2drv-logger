// Log.cpp: implementation of the CLog class.
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

//#include <expat.h>
#include <vscpbase64.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include <json.hpp>  // Needs C++11  -std=c++11
#include <mustache.hpp>

#include "log.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;


// Buffer size for XML parser
//#define XML_BUFF_SIZE 10000

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
// CLog
//

CLog::CLog()
{
    m_bQuit      = false;
    m_bWrite     = false;
    m_bQuit      = false;
    m_bOverWrite = false;
    m_logFmt = logFmtString;

    vscp_clearVSCPFilter(&m_vscpfilterTx);  // Accept all TX events

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);
}

//////////////////////////////////////////////////////////////////////
// ~CLog
//

CLog::~CLog()
{

    close();

    pthread_mutex_destroy(&m_mutexSendQueue);
    pthread_mutex_destroy(&m_mutexReceiveQueue);

    sem_destroy(&m_semSendQueue);
    sem_destroy(&m_semReceiveQueue);
}


//////////////////////////////////////////////////////////////////////
// open
//

bool
CLog::open(std::string& pathcfg, cguid& guid)
{
    // Set GUID
    m_guid = guid;

    // Save config path
    m_pathConfigFile = pathcfg;

    // Read configuration file
    if (!doLoadConfig()) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] Failed to load configuration file [%s]",
               m_pathConfigFile.c_str());
    }

    // Not allowed to have append and VSCP Works format
    if (m_logFmt != logFmtString) {
        m_bOverWrite = true;
        syslog(LOG_ERR,
               "[vscpl2drv-logger] VSCP Works format require that "
               "overwrite=\"true\". Now forced to true.");
    }

    // start the worker thread
    if (pthread_create(&m_pWrkThread, NULL, threadWorker, this)) {
        syslog(LOG_CRIT, "Unable to start logger driver worker thread.");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CLog::close(void)
{
    if (m_logStream.is_open()) {
        
        switch(m_logFmt) {
            case logFmtString:
                break;
            case logFmtXml:
                m_logStream.write("</vscprxdata>\n", strlen("</vscprxdata>\n"));
                break;
    
            case logFmtJson:
                m_logStream << "]\n";
                break;
        }

        // Close the log-file
        m_logStream.close();
    }

    // Do nothing if already terminated
    if (m_bQuit) {
        return;
    }

    m_bQuit = true; // terminate the thread
    pthread_join(m_pWrkThread, NULL);
}

//////////////////////////////////////////////////////////////////////
// doFilter
//

bool
CLog::doFilter(vscpEvent* pEvent)
{
    return true;
}

//////////////////////////////////////////////////////////////////////
// setFilter
//

void
CLog::setFilter(vscpEvent* pFilter)
{
    return;
}

//////////////////////////////////////////////////////////////////////
// setMask
//

void
CLog::setMask(vscpEvent* pMask)
{
    return;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
CLog::doLoadConfig(void)
{
    try {
        std::ifstream in(m_pathConfigFile, std::ifstream::in);
        in >> m_j_config;
    }
    catch (...) {
        syslog(LOG_ERR, "[vscpl2drv-automation] Failed to parse JSON configuration.");
        return false;
    }

    try {
        if (m_j_config.contains("debug") && m_j_config["debug"].is_boolean()) { 
            m_bDebug = m_j_config["debug"].get<bool>();
        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'debug'. Default will be used.");
        }

        if (m_bDebug) {
            syslog(LOG_DEBUG, "ReadConfig: 'debug' set to %s", m_bDebug ? "true" : "false");
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'debug'. Default will be used.");
    }

    try {
        if (m_j_config.contains("write") && m_j_config["write"].is_boolean()) { 
            m_bWrite = m_j_config["write"].get<bool>();
        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'write'. Default will be used.");
        }

        if (m_bDebug) {
            syslog(LOG_DEBUG, "ReadConfig: 'write' set to %s", m_bWrite ? "true" : "false");
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'write'. Default will be used.");
    }

    try {
        if (m_j_config.contains("path") && m_j_config["path"].is_string()) { 
            m_pathLogFile = m_j_config["path"].get<std::string>();
        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'path'. Must be set.");
            return false;
        }

        if (m_bDebug) {
            syslog(LOG_DEBUG, "ReadConfig: 'path' set to %s", m_pathLogFile.c_str());
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'path'. Must be set.");
        return false;
    }

    try {
        if (m_j_config.contains("overwrite") && m_j_config["overwrite"].is_boolean()) { 
            m_bOverWrite = m_j_config["overwrite"].get<bool>();
        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'overwrite'. Default will be used.");
        }

        if (m_bDebug) {
            syslog(LOG_DEBUG, "ReadConfig: 'overwrite' set to %s", m_bOverWrite ? "true" : "false");
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'overwrite'. Default will be used.");
    }

    try {
        if (m_j_config.contains("logfmt") && m_j_config["logfmt"].is_number()) { 
            int logFmt = m_j_config["logfmt"].get<int>();
            switch (logFmt) {
                case 1:     // XML
                    m_logFmt = logFmtXml;
                    break;

                case 2:     // JSON
                    m_logFmt = logFmtJson;
                    break;

                default:
                    syslog(LOG_ERR, "ReadConfig: Log format set to default due to invalid config value.");

                case 0:     // String
                    m_logFmt = logFmtString;
                    break;
            }

        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'logfmt'. Default will be used.");
        }

        if (m_bDebug) {
            syslog(LOG_DEBUG, "ReadConfig: 'logfmt' set to %d", m_logFmt);
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'worksfmt'. Default will be used.");
    }

    try {
        if (m_j_config.contains("filter") && m_j_config["filter"].is_string()) { 
            std::string str = m_j_config["filter"].get<std::string>();
            if (str.length()) {
                if (!vscp_readFilterFromString(&m_vscpfilterTx, str)) {
                    syslog(LOG_ERR, "ReadConfig: Failed to read 'filter' from string.");
                }
            }
            else {
                syslog(LOG_ERR, "ReadConfig: Failed to read 'filter' zero length.");
            }
        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'filter'.");
        }

        if (m_bDebug) {
            std::string str;
            vscp_writeFilterToString(str, &m_vscpfilterTx);
            syslog(LOG_DEBUG, "ReadConfig: 'filter' set to %s", str.c_str());
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'filter'.");
    }

    try {
        if (m_j_config.contains("mask") && m_j_config["mask"].is_string()) { 
            std::string str = m_j_config["mask"].get<std::string>();
            if (str.length()) {
                if (!vscp_readMaskFromString(&m_vscpfilterTx, str)) {
                    syslog(LOG_ERR, "ReadConfig: Failed to read 'mask' from string.");
                }
            }
            else {
                syslog(LOG_ERR, "ReadConfig: Failed to read 'mask' zero length.");
            }
        } 
        else {
            syslog(LOG_ERR, "ReadConfig: Failed to read 'mask'.");
        }

        if (m_bDebug) {
            std::string str;
            vscp_writeMaskToString(str, &m_vscpfilterTx);
            syslog(LOG_DEBUG, "ReadConfig: 'mask' set to %s", str.c_str());
        }
    }
    catch (...) {
        syslog(LOG_ERR, "ReadConfig: Failed to read 'mask'.");
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CLog::doSaveConfig(void)
{
    std::string str;
    json j;

    j["debug"] = m_bDebug;
    j["write"] = m_bWrite;
    j["path"] = m_pathConfigFile;
    j["overwrite"] = m_bOverWrite;
    j["logfmt"] = m_logFmt;
    vscp_writeFilterToString(str, &m_vscpfilterTx);
    j["filter"] = str;
    vscp_writeMaskToString(str, &m_vscpfilterTx);
    j["mask"] = str;

    try {
        std::ofstream fs;
        fs.open(m_pathConfigFile);
        fs << j.dump();
        fs.close();
    } catch (...) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to save configuration file.");
        return false;
    }

    return true;
}


///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CLog::handleHLO(vscpEvent* pEvent)
{
    json j;
    //uint8_t outbuf[2048];  // Encryption/decryption buffer
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent) {
        syslog(LOG_ERR, "[vscpl2drv-logger] HLO handler: NULL event pointer.");
        return false;
    }

    // GUID + type = 17 + dummy payload size=10 {"op:":""}
    if (pEvent->sizeData < (17+10)) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: HLO buffer size is wrong.");
        return false;
    }

    // Check pointers
    if (NULL == pEvent->pdata) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: HLO in-buffer pointer is NULL.");
        return false;
    }

    // Event must be addressed to us
    cguid guid(pEvent->pdata);
    if (guid != m_guid) {
        return true;
    }

    uint8_t pkt_type = (pEvent->pdata[16] >> 4) & 0x0f;
    uint8_t pkt_encryption = pEvent->pdata[16] & 0x0f;

    // Check that type is JSON as we only accept JSON encoded HLO
    if (pkt_type != VSCP_HLO_TYPE_JSON) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] Only JSON formatted HLO understod.");
        return false;
    }

    // Parse HLO
    try {
        char buf[512];
        memset(buf, 0, sizeof(buf));
        //size_t len;
        //vscp_base64_decode(pEvent->pdata + 17, pEvent->sizeData-17, buf, &len);
        memcpy(buf, pEvent->pdata + 17, pEvent->sizeData-17);
        std::string str = std::string((const char *)buf);
        j = json::parse(str);
    }
    catch (...) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: Unable to parse JSON data.");
        return false;
    }

    std::string hlo_op;
    std::list<std::string> hlo_args;

    // Get op
    if (!j["op"].is_string()) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] HLO parser: No operation specified (not string).");
        return false;
    }

    hlo_op = j["op"];
    vscp_trim(hlo_op);
    vscp_makeLower(hlo_op);

    // Get arg(s)  - empty list if no args
    if (j["arg"].is_string()) {
        hlo_args.push_back(j["arg"]);
    } 
    else if (j["arg"].is_array()) {
        for (json::iterator it = j["arg"].begin(); it != j["arg"].end(); ++it) {
            hlo_args.push_back(*it);
        }
    }

    json j_rply;

    // Prepare reply
    ex.obid      = 0;
    ex.head      = VSCP_HEADER16_DUMB;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex);  // Set time to current time
    ex.vscp_class = VSCP_CLASS2_HLO;
    ex.vscp_type  = VSCP2_TYPE_HLO_RESPONSE;
    
    // ------------------------------------------------------------------------
    if ("noop" == hlo_op) {
        // Send positive response
        j_rply["op"] = "noop";
        j_rply["rv"] = VSCP_ERROR_SUCCESS;
    }
    // ------------------------------------------------------------------------
    else if ( "readvar" == hlo_op ) {
        if (!hlo_args.size()) {
            // Must be at least one argument
            // Send positive response
            j_rply["op"] = "readvar";
            j_rply["rv"] = VSCP_ERROR_INVALID_SYNTAX;
            j_rply["note"] = "radvar needs one argument. readvar 'name-of-var'";
        } 
        else {
            std::string var_name = hlo_args.front();
            vscp_trim(var_name);
            vscp_makeLower(var_name);

            j_rply["op"] = hlo_op;

            if ("debug" == var_name) {
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "debug";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
                j_rply["arg"]["value"] = m_bDebug ? true : false;
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ | PERMISSION_OTHER_WRITE;
            } 
            else if ("write" == var_name) {
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "write";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
                j_rply["arg"]["value"] = m_bWrite ? true : false;
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ;
            } 
            else if ("overwrite" == var_name) {
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "overwrite";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
                j_rply["arg"]["value"] = m_bOverWrite ? true : false;
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ | PERMISSION_OTHER_WRITE;
            } 
            else if ("logfmt" == var_name) {
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "logfmt";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_UINT8;
                j_rply["arg"]["value"] = m_logFmt;
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ | PERMISSION_OTHER_WRITE;
            } 
            else if ("path" == var_name) {
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "path";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
                j_rply["arg"]["value"] = vscp_convertToBase64(m_pathLogFile);
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ | PERMISSION_OTHER_WRITE;
            } 
            else if ("filter" == var_name) {
                std::string str;
                vscp_writeFilterToString(str, &m_vscpfilterTx);
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "filter";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
                j_rply["arg"]["value"] = vscp_convertToBase64(str);
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ | PERMISSION_OTHER_WRITE;
            } 
            else if ("mask" == var_name) {
                std::string str;
                vscp_writeMaskToString(str, &m_vscpfilterTx);
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "mask";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
                j_rply["arg"]["value"] = vscp_convertToBase64(str);
                j_rply["arg"]["attr"] = PERMISSION_OTHER_READ | PERMISSION_OTHER_WRITE;
            } 
            else {
                // Unknown variable
                j_rply["op"] = "readvar";
                j_rply["rv"] = VSCP_ERROR_UNKNOWN_ITEM;
                j_rply["note"] = "Unknown variable.";
            }
        }
    }
    // ------------------------------------------------------------------------
    else if ( "writevar" == hlo_op ) {

        if (hlo_args.size() < 2) {
            // Must be at least two arguments (name,value)
            // Send positive response
            j_rply["op"] = "writevar";
            j_rply["rv"] = VSCP_ERROR_INVALID_SYNTAX;
            j_rply["note"] = "radvar needs two arguments. writevar 'name-of-var' 'value'";
        } /* else if (!m_bWrite) {
            // Must be write enabled
            j_rply["op"] = "writevar";
            j_rply["rv"] = VSCP_ERROR_WRITE_ERROR;
            j_rply["note"] = "Write operations is disabled.";
        } */ 
        else {
            // Get variable name
            std::string var_name = hlo_args.front();
            hlo_args.pop_front();
            vscp_trim(var_name);
            vscp_makeLower(var_name);

            // Get variable value
            std::string var_value = hlo_args.front();
            hlo_args.pop_front();
            
            if ("debug" == var_name) {
                if (std::string::npos != var_value.find("true")) {
                    m_bDebug = true;
                } 
                else {
                    m_bDebug = false;
                }
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "debug";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
                j_rply["arg"]["value"] = m_bDebug ? true : false;
            } 
            else if ("write" == var_name) {
                // 'write' is read only
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_READ_ONLY;
                j_rply["note"] = "The 'write' variable is read-only";
                j_rply["arg"]["name"] = "write";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
                j_rply["arg"]["value"] = m_bWrite ? true : false;
            } 
            else if ("overwrite" == var_name) {
                if (std::string::npos != var_value.find("true")) {
                    m_bOverWrite = true;
                } 
                else {
                    m_bOverWrite = false;
                }
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "overwrite";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_BOOLEAN;
                j_rply["arg"]["value"] = m_bOverWrite ? true : false;
            } 
            else if ("logfmt" == var_name) {
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                int fmt = vscp_readStringValue(var_value);
                switch (fmt) {
                    case 0:
                        m_logFmt = logFmtString;
                        j_rply["rv"] = VSCP_ERROR_SUCCESS;
                        break;
                    case 1:
                        m_logFmt = logFmtXml;
                        j_rply["rv"] = VSCP_ERROR_SUCCESS;
                        break;
                    case 2:
                        m_logFmt = logFmtJson;
                        j_rply["rv"] = VSCP_ERROR_SUCCESS;
                        break;
                    default:
                        j_rply["rv"] = VSCP_ERROR_INVALID_SYNTAX;
                        j_rply["note"] = "Invalid log format.";
                        break;
                }
                j_rply["op"] = "writevar";
                j_rply["arg"]["name"] = "logfmt";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_UINT8;
                j_rply["arg"]["value"] = vscp_str_format("%d", m_logFmt);
            } 
            else if ("path" == var_name) {
                vscp_base64_std_decode(var_value);
                m_pathLogFile = var_value;
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "path";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
                j_rply["arg"]["value"] = vscp_convertToBase64(m_pathLogFile);
            } 
            else if ("filter" == var_name) {
                std::string str;
                vscp_base64_std_decode(var_value);
                vscp_readFilterFromString(&m_vscpfilterTx, var_value);
                vscp_writeFilterToString(str, &m_vscpfilterTx);
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "filter";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
                j_rply["arg"]["value"] = vscp_convertToBase64(str);

            } 
            else if ("mask" == var_name) {
                std::string str;
                vscp_base64_std_decode(var_value);
                vscp_readMaskFromString(&m_vscpfilterTx, var_value);
                vscp_writeMaskToString(str, &m_vscpfilterTx);
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
                j_rply["arg"]["name"] = "mask";
                j_rply["arg"]["type"] = VSCP_REMOTE_VARIABLE_CODE_STRING;
                j_rply["arg"]["value"] = vscp_convertToBase64(str);
            } 
            else {
                // Unknown variable
                j_rply["op"] = "writevar";
                j_rply["rv"] = VSCP_ERROR_UNKNOWN_ITEM;
                j_rply["note"] = "Unknown variable.";
            }
        }
    }
    // ------------------------------------------------------------------------
    else if ("save" == hlo_op) {
        if (!m_bWrite) {
            // Must be write enabled
            j_rply["op"] = "save";
            j_rply["rv"] = VSCP_ERROR_WRITE_ERROR;
            j_rply["note"] = "Write operations is disabled.";
        } 
        else {            
            if (doSaveConfig()) {
                if (m_bDebug) {
                    syslog(LOG_ERR,
                        "[vscpl2drv-logger] HLO_OP_SAVE - Saving "
                        "configuration. Success.");
                }
                // OK
                j_rply["op"] = "save";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
            }
            else {
                if (m_bDebug) {
                    syslog(LOG_DEBUG,
                        "[vscpl2drv-logger] HLO_OP_SAVE - Saving "
                        "configuration. Failure.");
                }
                // ERROR
                j_rply["op"] = "save";
                j_rply["rv"] = VSCP_ERROR_ERROR;
                j_rply["note"] = "Failed to save configuration.";
            }
        }
    }
    // ------------------------------------------------------------------------
    else if ( "load" == hlo_op ) {
        if ( doLoadConfig() ) {
            if (m_bDebug) {
                    syslog(LOG_DEBUG,
                        "[vscpl2drv-logger] HLO_OP_LOAD - Saving "
                        "configuration. Success.");
                }
            // OK
            j_rply["op"] = "load";
            j_rply["rv"] = VSCP_ERROR_SUCCESS;
            j_rply["note"] = "Successfully loaded configuration.";
        }
        else {
            if (m_bDebug) {
                    syslog(LOG_DEBUG,
                        "[vscpl2drv-logger] HLO_OP_LOAD - Loading "
                        "configuration. Failure.");
            }
            // ERROR
            j_rply["op"] = "load";
            j_rply["rv"] = VSCP_ERROR_ERROR;
            j_rply["note"] = "Failed to load configuration.";
        }
    } 
    // ------------------------------------------------------------------------
    else if ( "open" == hlo_op ) {  
        if (!m_logStream.is_open()) {
            if (openLogFile()) {
                if (m_bDebug) {
                    syslog(LOG_DEBUG,
                            "[vscpl2drv-logger] HLO-CMD OPEN - Opening logfile "
                            "[%s][%s] .",
                            m_pathLogFile.c_str(),
                            (m_logStream.is_open() ? "open" : "closed"));                                
                }
                // OK
                j_rply["op"] = "open";
                j_rply["rv"] = VSCP_ERROR_SUCCESS;
            }
            else {
                syslog(LOG_ERR,
                        "[vscpl2drv-logger] HLO-CMD OPEN - Failed to "
                        "open logfile [%s].",
                        m_pathLogFile.c_str());
                // ERROR
                j_rply["op"] = "open";
                j_rply["rv"] = VSCP_ERROR_ERROR;
                j_rply["note"] = vscp_str_format("Failed to open logfile %s.",m_pathLogFile.c_str());                        
            }
        }
        else {
            syslog(LOG_ERR,
                        "[vscpl2drv-logger] HLO-CMD OPEN - logfile "
                        "already open [%s].",
                        m_pathLogFile.c_str());
            // ERROR
            j_rply["op"] = "open";
            j_rply["rv"] = VSCP_ERROR_ERROR;
            j_rply["note"] = vscp_str_format("Logfile is already open %s.",m_pathLogFile.c_str());
        }
    }
    // ------------------------------------------------------------------------
    else if ( "close" == hlo_op ) {
        if (m_bDebug) {
            syslog(LOG_ERR,
                    "[vscpl2drv-logger] HLO-CMD CLOSE - Closing "
                    "logfile [%s][%s] .",
                    m_pathLogFile.c_str(),
                    (m_logStream.is_open() ? "open" : "closed"));
        }

        if (m_logStream.is_open()) {
            m_logStream.close();
        }

        // OK
        j_rply["op"] = "close";
        j_rply["rv"] = VSCP_ERROR_SUCCESS;
    }
    else {
        // Unknow command
        if (m_bDebug) {
            syslog(LOG_ERR,
                    "[vscpl2drv-logger] HLO-CMD unknown command "
                    "logfile [%s][%s] .",
                    hlo_op.c_str(),
                    m_pathLogFile.c_str());
        }
        // ERROR
        j_rply["op"] = hlo_op;
        j_rply["rv"] = VSCP_ERROR_UNKNOWN_ITEM;
    }

    std::string rply = j_rply.dump();

    memset(ex.data, 0, sizeof(ex.data));
    ex.sizeData = 17 + rply.length();
    if (ex.sizeData > (VSCP_LEVEL2_MAXDATA-17)) {
        syslog(LOG_ERR, "[vscpl2drv-logger] HLO: Reply data is larger than allowed maximum.");
        ex.sizeData = VSCP_LEVEL2_MAXDATA-17;
    }

    // Write in GUID
    m_guid.writeGUID(ex.GUID);
    memcpy(ex.data, pEvent->GUID, 16);

    // Set type byte
    ex.data[16] = pEvent->pdata[16];

    // Copy in data
    memcpy(ex.data+17, rply.c_str(), rply.length());

    // Put event in receive queue
    return eventExToReceiveQueue(ex);
}

///////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

size_t
CLog::readEncryptionKey(const std::string& path)
{
    size_t keySize = 0;
    std::string line;

    if (path.size()) {

        std::string line;
        std::ifstream keyfile(path);

        if (keyfile.is_open()) {
            getline(keyfile, line);
            vscp_trim(line);
            keySize = vscp_hexStr2ByteArray(m_key, 32, line.c_str());
            keyfile.close();
        } 
        else {
            syslog(LOG_ERR, "[vscpl2drv-logger] Failed to get encryption key.");
        }
    }

    return keySize;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CLog::eventExToReceiveQueue(const vscpEventEx& ex)
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
    } 
    else {
        syslog(LOG_ERR, "[vscpl2drv-logger] Unable to allocate event storage.");
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
CLog::addEvent2SendQueue(const vscpEvent* pEvent)
{
    vscpEvent *pev = new vscpEvent;
    if (NULL == pev) return false;

    pev->pdata = NULL;
    pev->sizeData = 0;

    if (!vscp_copyEvent(pev, pEvent)) {
        return false;
    }

    pthread_mutex_lock(&m_mutexSendQueue);
    m_sendList.push_back((vscpEvent*)pev);
    sem_post(&m_semSendQueue);
    pthread_mutex_unlock(&m_mutexSendQueue);
    
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//

bool
CLog::addEvent2ReceiveQueue(const vscpEvent* pEvent)
{
    vscpEvent *pev = new vscpEvent;
    if (NULL == pev) return false;

    pev->pdata = NULL;
    pev->sizeData = 0;

    if (!vscp_copyEvent(pev, pEvent)) {
        return false;
    }

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
CLog::openLogFile(void)
{
    try {
        if (m_bOverWrite) {

            m_logStream.open(m_pathLogFile, std::ios::out | std::ios::trunc);
            if (!m_logStream.is_open()) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] Failed to open log file [%s].",
                       m_pathLogFile.c_str());
                return false;
            }

            if (m_bDebug) {
                syslog(LOG_DEBUG,
                       "Successfully opened logfile [%s]",
                       m_pathLogFile.c_str());
            }

            switch (m_logFmt) {
                case logFmtString:
                    break;
                case logFmtXml:
                    m_logStream << "<?xml version = \"1.0\" encoding = \"UTF-8\" ?>\n";
                    // RX data start
                    m_logStream << "<vscprxdata>\n";
                    m_logStream.flush();
                    break;
                case logFmtJson:
                    m_logStream << "[\n";
                    break;
            }

        } 
        else {

            m_logStream.open(m_pathLogFile, std::ios::out | std::ios::app);
            if (!m_logStream.is_open()) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] Failed to open log file [%s].",
                       m_pathLogFile.c_str());
                return false;
            }

            if (m_bDebug) {
                syslog(LOG_DEBUG,
                       "Successfully opened logfile [%s]",
                       m_pathLogFile.c_str());
            }
        }
    } catch (...) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to open log file!");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// writeEvent2Log
//

bool
CLog::writeEvent2Log(vscpEvent* pEvent)
{
    std::string str;

    if (m_logStream.is_open()) {

        if (m_logFmt == logFmtString) {

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
        else if (m_logFmt == logFmtXml) {

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

            m_logStream << "<sizedata>";    // Not used by read routine
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

        } 
        else if (m_logFmt == logFmtJson) {
            if ( vscp_convertEventToJSON(str, pEvent) ) {
                json j;

                j["direction"] = "rx";
                j["event"] = json::parse(str);

                m_logStream << j.dump();
                m_logStream << ",";
                m_logStream.flush();
            } 
            else {
                syslog(LOG_ERR, "[vscpl2drv-logger] Failed to convert event to JSON.");
            }
        } 
        else {
            syslog(LOG_ERR, "[vscpl2drv-logger] Invalid log format set.");
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
//                               Worker thread
///////////////////////////////////////////////////////////////////////////////

void*
threadWorker(void* pData)
{
    CLog* pLog = (CLog*)pData;
    if (NULL == pLog) {
        syslog(LOG_ERR,
               "[vscpl2drv-logger] No thread object supplied to worker thread. "
               "Aborting!");
        return NULL;
    }

    // Open the file
    if (!pLog->openLogFile()) {
        syslog(LOG_ERR, "[vscpl2drv-logger] Failed to open log file. Aborting");
        return NULL;
    }

    while (!pLog->m_bQuit) {
        // Wait for events
        int rv;
        if (-1 == (rv = vscp_sem_wait(&pLog->m_semSendQueue, 500))) {
            if (ETIMEDOUT == errno) {
                continue;
            } 
            else if (EINTR == errno) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] Interrupted by a signal handler");
                continue;
            } 
            else if (EINVAL == errno) {
                syslog(LOG_ERR,
                       "[vscpl2drv-logger] Invalid semaphore (timout)");
                break;
            } 
            else if (EAGAIN == errno) {
                syslog(LOG_ERR, "[vscpl2drv-logger] Blocking error");
                break;
            } 
            else {
                syslog(LOG_ERR, "[vscpl2drv-logger] Unknown error");
                break;
            }
        }

        if (pLog->m_sendList.size()) {
            pthread_mutex_lock(&pLog->m_mutexSendQueue);
            vscpEvent* pEvent = pLog->m_sendList.front();
            pLog->m_sendList.pop_front();
            pthread_mutex_unlock(&pLog->m_mutexSendQueue);

            if (NULL == pEvent) {
                continue;
            }

            // Only HLO object event is of interst to us
            if ((VSCP_CLASS2_HLO == pEvent->vscp_class) &&
                (VSCP2_TYPE_HLO_COMMAND == pEvent->vscp_type) &&
                vscp_isSameGUID(pLog->m_guid.getGUID(), pEvent->pdata)) {
                    pLog->handleHLO(pEvent);
                    // Fall through and log event...
                }

            pLog->writeEvent2Log(pEvent);

            vscp_deleteEvent_v2(&pEvent);
            pEvent = NULL;
        }   // Event received
    }   // Receive loop

    return NULL;
}
