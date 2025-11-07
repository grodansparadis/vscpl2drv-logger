// vscpl2-loggerdrv.cpp : Defines the initialization routines for the DLL.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2025 Ake Hedman,
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
//

#include <fstream>
#include <map>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "version.h"
#include "vscpl2drv-logger.h"
#include <canal-macro.h>
#include "../common/log.h"

#ifndef _WIN32
void _init() __attribute__((constructor));
void _fini() __attribute__((destructor));
#else
// On Windows, these will be called from DllMain
void _init();
void _fini();
#endif

// This map holds driver handles/objects
static std::map<long, CLog *> g_ifMap;

// Mutex for the map object
#ifdef _WIN32
static HANDLE g_mapMutex;
#else
static pthread_mutex_t g_mapMutex;
#endif

////////////////////////////////////////////////////////////////////////////
// DLL constructor
//

void _init() { 
#ifdef _WIN32
  g_mapMutex = CreateMutex(NULL, FALSE, NULL);
#else
  pthread_mutex_init(&g_mapMutex, NULL);
#endif
}

////////////////////////////////////////////////////////////////////////////
// DLL destructor
//

void _fini() {
  // If empty - nothing to do
  if (g_ifMap.empty())
    return;

  // Remove orphan objects

  LOCK_MUTEX(g_mapMutex);

  for (std::map<long, CLog *>::iterator it = g_ifMap.begin();
       it != g_ifMap.end(); ++it) {
    // std::cout << it->first << " => " << it->second << '\n';

    CLog *pif = it->second;
    if (NULL != pif) {
      delete pif;
      pif = NULL;
    }
  }

  g_ifMap.clear(); // Remove all items

  UNLOCK_MUTEX(g_mapMutex);
#ifdef _WIN32
  CloseHandle(g_mapMutex);
#else
  pthread_mutex_destroy(&g_mapMutex);
#endif
}

#ifdef _WIN32
///////////////////////////////////////////////////////////////////////////////
// DllMain - Windows DLL entry point
//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      _init();
      break;
    case DLL_PROCESS_DETACH:
      _fini();
      break;
    default:
      break;
  }
  return TRUE;
}
#endif

///////////////////////////////////////////////////////////////////////////////
// addDriverObject
//

long addDriverObject(CLog *pif) {
  std::map<long, CLog *>::iterator it;
  long h = 0;

  LOCK_MUTEX(g_mapMutex);

  // Find free handle
  while (true) {
    if (g_ifMap.end() == (it = g_ifMap.find(h)))
      break;
    h++;
  };

  g_ifMap[h] = pif;
  h += 1681;

  UNLOCK_MUTEX(g_mapMutex);

  return h;
}

///////////////////////////////////////////////////////////////////////////////
// getDriverObject
//

CLog *getDriverObject(long h) {
  std::map<long, CLog *>::iterator it;
  long idx = h - 1681;

  // Check if valid handle
  if (idx < 0)
    return NULL;

  it = g_ifMap.find(idx);
  if (it != g_ifMap.end()) {
    return it->second;
  }

  return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// removeDriverObject
//

void removeDriverObject(long h) {
  std::map<long, CLog *>::iterator it;
  long idx = h - 1681;

  // Check if valid handle
  if (idx < 0)
    return;

  LOCK_MUTEX(g_mapMutex);
  it = g_ifMap.find(idx);
  if (it != g_ifMap.end()) {
    CLog *pObj = it->second;
    if (NULL != pObj) {
      delete pObj;
      pObj = NULL;
    }
    g_ifMap.erase(it);
  }
  UNLOCK_MUTEX(g_mapMutex);
}

///////////////////////////////////////////////////////////////////////////////
//                         V S C P   D R I V E R -  A P I
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// VSCPOpen
//

extern "C" long VSCPOpen(const char *pPathConfig, const char *pguid) {
  long h = 0;

  CLog *pdrvObj = new CLog();
  if (NULL != pdrvObj) {

    std::string cfg(pPathConfig);
    cguid guid((const uint8_t *)pguid);

    if (pdrvObj->open(cfg, guid)) {

      if (!(h = addDriverObject(pdrvObj))) {
        delete pdrvObj;
      }

    } else {
      delete pdrvObj;
    }
  }

  return h;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPClose
//

extern "C" int VSCPClose(long handle) {
  CLog *pdrvObj = getDriverObject(handle);
  if (NULL == pdrvObj)
    return 0;
  pdrvObj->close();
  removeDriverObject(handle);
  return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPWrite
//

extern "C" int VSCPWrite(long handle, const vscpEvent *pEvent,
                         unsigned long timeout) {
  CLog *pdrvObj = getDriverObject(handle);
  if (NULL == pdrvObj) {
    return CANAL_ERROR_MEMORY;
  }
  pdrvObj->addEvent2SendQueue(pEvent);

  return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPRead
//

extern "C" int VSCPRead(long handle, vscpEvent *pEvent, unsigned long timeout) {
  // Check pointer
  if (NULL == pEvent)
    return CANAL_ERROR_PARAMETER;

  CLog *pdrvObj = getDriverObject(handle);
  if (NULL == pdrvObj)
    return CANAL_ERROR_MEMORY;

  int rv;
  if (-1 == (rv = vscp_sem_wait(&pdrvObj->m_semReceiveQueue, timeout))) {
    if (ETIMEDOUT == errno) {
      return CANAL_ERROR_TIMEOUT;
    }
#ifndef _WIN32
    else if (EINTR == errno) {
      SYSLOG(LOG_ERR, "[vscpl2drv-logger] Interrupted by a signal handler");
      return CANAL_ERROR_INTERNAL;
    } else if (EINVAL == errno) {
      SYSLOG(LOG_ERR, "[vscpl2drv-logger] Invalid semaphore (timout)");
      return CANAL_ERROR_INTERNAL;
    } else if (EAGAIN == errno) {
      SYSLOG(LOG_ERR, "[vscpl2drv-logger] Blocking error");
      return CANAL_ERROR_INTERNAL;
    } else {
      SYSLOG(LOG_ERR, "[vscpl2drv-logger] Unknown error");
      return CANAL_ERROR_INTERNAL;
    }
#endif
  }

  pthread_mutex_lock(&pdrvObj->m_mutexReceiveQueue);
  vscpEvent *pLocalEvent = pdrvObj->m_receiveList.front();
  pdrvObj->m_receiveList.pop_front();
  pthread_mutex_unlock(&pdrvObj->m_mutexReceiveQueue);
  if (NULL == pLocalEvent)
    return CANAL_ERROR_MEMORY;

  vscp_copyEvent(pEvent, pLocalEvent);
  vscp_deleteEvent(pLocalEvent);

  return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// VSCPGetVersion
//

extern "C" unsigned long VSCPGetVersion(void) {
  unsigned long ver = VSCPL2DRV_LOGGER_MAJOR_VERSION << 24 | VSCPL2DRV_LOGGER_MINOR_VERSION << 16 |
                      VSCPL2DRV_LOGGER_RELEASE_VERSION << 8 | VSCPL2DRV_LOGGER_BUILD_VERSION;
  return ver;
}
