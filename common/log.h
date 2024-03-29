// Log.h: interface for the CVSCPLog class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2023 Ake Hedman,
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

#if !defined(VSCPLOG_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
#define VSCPLOG_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_

#include <vscp.h>
#include <vscpremotetcpif.h>

#include <nlohmann/json.hpp>  // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <fstream>
#include <list>
#include <string>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;


#define VSCP_LEVEL2_DLL_LOGGER_OBJ_MUTEX "___VSCP__DLL_L2LOGGER_OBJ_MUTEX____"

#define VSCP_LOG_LIST_MAX_MSG 2048

// Log file formats
enum log_file_format {logFmtString = 0, logFmtXml, logFmtJson};

// Forward declarations
class CHLO;

class CLog
{
  public:
    /// Constructor
    CLog();

    /// Destructor
    virtual ~CLog();

    /*!
      Filter message
      @param pEvent Pointer to VSCP event
      @return True if message is accepted false if rejected
    */
    bool doFilter(vscpEvent* pEvent);

    /*!
      Set Filter
    */
    void setFilter(vscpEvent* pFilter);

    /*!
        Set Mask
    */
    void setMask(vscpEvent* pMask);

    /*!
      Open/create the logfile
      @param pathcfg Path to configuration file
      @param guid Unique GUID for driver.
      @return True on success.
    */
    bool open(std::string& pathcfg, cguid& guid);

    /*!
      Flush and close the log file
     */
    void close(void);

    /*!
      Add one event to the output queue
      @param pEvent Pointer to VSCP event
      @return True on success.S
     */
    bool addEvent2Queue(const vscpEvent* pEvent);

    /*!
      Write an event out to the file
      @param pEvent Pointer to VSCP event
      @return True on success.
     */
    bool writeEvent2Log(vscpEvent* pEvent);

    /*!
      Add event to send queue
      @param pEvent Pointer to event that should be added
      @result True on success, false on failure
    */
    bool addEvent2SendQueue(const vscpEvent* pEvent);

    /*!
      Add event to receive queue
      @param pEvent Pointer to event that should be added
      @result True on success, false on failure
    */
    bool addEvent2ReceiveQueue(const vscpEvent* pEvent);


    /*!
      Handle HLO commands sent to this driver
      @param pEvent HLO event
      @return true on success, false on failure
    */
    bool handleHLO(vscpEvent* pEvent);  

    /*!
      Put event on receive queue and signal
      that a new event is available
      @param ex Event to send
      @return true on success, false on failure
    */
    bool eventExToReceiveQueue(const vscpEventEx& ex);

    /*!
      Load configuration
      @return true on success, false on failure
    */
    bool doLoadConfig(void);

    /*!
      Save the configuration file.
    */
    bool doSaveConfig(void);

    /*!
      Open the log file
      @return true on success.
    */
    bool openLogFile(void);

    /*!
      Read encryption key
      @return key size or zero on failure.
    */
    size_t readEncryptionKey(const std::string& path);

  public:

    /////////////////////////////////////////////////////////
    //                      Logging
    /////////////////////////////////////////////////////////
    
    bool m_bEnableFileLog;                    // True to enable logging
    spdlog::level::level_enum m_fileLogLevel; // log level
    std::string m_fileLogPattern;             // log file pattern
    std::string m_path_to_log_file;           // Path to logfile      
    uint32_t m_max_log_size;                  // Max size for logfile before rotating occures 
    uint16_t m_max_log_files;                 // Max log files to keep

    bool m_bConsoleLogEnable;                     // True to enable logging to console
    spdlog::level::level_enum m_consoleLogLevel;  // Console log level
    std::string m_consoleLogPattern;              // Console log pattern

    // ------------------------------------------------------------------------

    // JSON configuration object
    json m_j_config;

    /// Run flag
    bool m_bQuit;

    /// True enables debug output to syslog
    bool m_bDebug;

    /// True enables config write
    bool m_bWrite;

    /// Rewrite the log file when the driver starts if enabled
    bool m_bOverWrite;

    /// Log file format (0=string, 1=xml, 2=json)
    log_file_format m_logFmt;

    /// Unique GUID for this driver
    cguid m_guid;

    /// Path to logfile
    std::string m_pathLogFile;

    /// Path to the configuration file
    std::string m_pathConfigFile;

    /// The log stream
    std::ofstream m_logStream;

    /*! 
      Key to encryption token
      empty for no encryption.
    */
    std::string m_pathKey;

    /*!
      Encryption key
      If set used to decrypt/encrypt HLO events
    */
    uint8_t m_key[32];

    /// Pointer to worker thread
    pthread_t m_pWrkThread;

    /// Filter
    vscpEventFilter m_filterIn;
    vscpEventFilter m_filterOut;

    // Queue
    std::list<vscpEvent*> m_sendList;
    std::list<vscpEvent*> m_receiveList;

    /*!
      Event object to indicate that there is an event in the
      output queue
    */
    sem_t m_semSendQueue;
    sem_t m_semReceiveQueue;

    // Mutex to protect the output queue
    pthread_mutex_t m_mutexSendQueue;
    pthread_mutex_t m_mutexReceiveQueue;
};



#endif // !defined(VSCPLOG_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
