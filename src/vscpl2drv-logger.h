// vscpl2drv-logger.h : main header file for the canallogger.dll
// Linux version
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

#if !defined(LOGGERDLL_H__A388C093_AD35_4672_8BF7_DBC702C6B0C8__INCLUDED_)
#define LOGGERDLL_H__A388C093_AD35_4672_8BF7_DBC702C6B0C8__INCLUDED_

#include "../common/log.h"

#define VSCP_DLL_SONAME "vscpl2drv_logger.1"

// This is the version info for this DLL - Change to your own value
#define VSCP_DLL_VERSION 0x000003

// This is the vendor string - Change to your own value
#define VSCP_DLL_VENDOR                                                        \
    "Grodans Paradis AB, Sweden, https://www.grodansparadis.com"

// Driver information.
#define VSCP_LOGGER_DRIVERINFO                                                   \
    "<?xml version = \"1.0\" encoding = \"UTF-8\" ?>"                          \
    "<!-- Version 1.0.0    2015-05-14   -->"                                   \
    "<config level=\"2\"blocking\"true|false\" description=\"bla bla bla "     \
    "bla\">"                                                                   \
    "   <item pos=\"0\" type=\"string\" description\"Logger driver\"/>"          \
    "   <item pos=\"1\" type=\"path\" description\"Path to configuration "     \
    "file\"/>"                                                                 \
    "</config>"

/*!
    Add a driver object

    @parm plog Object to add
    @return handle or 0 for error
*/
long
addDriverObject(CLog *pif);

/*!
    Get a driver object from its handle

    @param handle for object
    @return pointer to object or NULL if invalid
            handle.
*/
CLog *
getDriverObject(long handle);

/*!
    Remove a driver object
    @param handle for object.
*/
void
removeDriverObject(long handle);

#endif // !defined(LOGGERDLL_H__A388C093_AD35_4672_8BF7_DBC702C6B0C8__INCLUDED_)
