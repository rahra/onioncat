/* Copyright 2008-2019 Bernhard R. Fischer.
 *
 * This file is part of OnionCat.
 *
 * OnionCat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * OnionCat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OnionCat. If not, see <http://www.gnu.org/licenses/>.
 */

/*! \file ocat_wintuntap.c
 * This file contains the Windows code for accessing the OpenVPN TAP driver.
 * This driver must be installed in order to run OnionCat on Windows.
 *
 *  The source code of this file was originally written by Wolfgang Ginolas for
 *  his P2PVPN project (http://www.p2pvpn.org/) and was by his permission
 *  adapted (thanks) to the needs for OnionCat.
 *  \author Bernhard R. Fischer, <bf@abenteuerland.at>
 *  \date 2019/09/08
 */
 
#ifdef __CYGWIN__

#include "ocat.h"

#include <windows.h>
#include <objbase.h>
#include <winioctl.h>


// this is the registry directory where the drivers reside in
#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
// this registry directory contains also information about network drivers
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
const char *tap_component_id_[] = {"tap0901", "tapoas", "tap0801", NULL};

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define TAPSUFFIX         ".tap"

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)


typedef struct TapData
{
    HANDLE fd;
    HANDLE read_event;
    HANDLE write_event;
    OVERLAPPED read_overlapped;
    OVERLAPPED write_overlapped;    
} TapData_t;


static TapData_t tapData_;


int findTapDevice(char *deviceID, int deviceIDLen, char *deviceName, int deviceNameLen, const char *tap_component_id)
{
   HKEY adapterKey, key;
   int i;
   DWORD len;
   char keyI[1024], keyName[1024], componentId[256];
    
   if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapterKey) != ERROR_SUCCESS)
   {
      log_msg(LOG_ERR, "RegOpenKeyEx \"%s\" failed. Error = %ld", ADAPTER_KEY, GetLastError());
      return -1;
   }

   deviceID[0] = '\0';
   for (i = 0; deviceID[0] == '\0' && 
         ERROR_SUCCESS == RegEnumKey(adapterKey, i, keyI, sizeof(keyI)); i++)
   {
      snprintf(keyName, sizeof(keyName), "%s\\%s", ADAPTER_KEY, keyI);

      if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key) != ERROR_SUCCESS)
      {
         log_msg(LOG_ERR, "RegOpenKeyEx \"%s\" failed. Error = %ld", keyName, GetLastError());
         return -1;
      }
        
      len = sizeof(componentId);
      if ((RegQueryValueEx(key, "ComponentId", NULL, NULL, componentId, &len) == ERROR_SUCCESS)
            && !strcmp(componentId, tap_component_id))
      {
         len = deviceIDLen;
         RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, deviceID, &len);
         log_debug("ComponentId = \"%s\", NetCfgInstanceId = \"%s\"", componentId, deviceID);
      }

      RegCloseKey(key);
   }    
    
   RegCloseKey(adapterKey);

   if (!deviceID[0])
      return -1;
    
   snprintf(keyName, sizeof(keyName), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, deviceID);
   if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key) != ERROR_SUCCESS)
   {
      log_msg(LOG_ERR, "RegOpenKeyEx \"%s\" failed. Error = %ld", keyName, GetLastError());
      return -1;
   }

   len = deviceNameLen;
   if (RegQueryValueEx(key, "Name", NULL, NULL, deviceName, &len) != ERROR_SUCCESS)
   {
      log_msg(LOG_ERR, "RegQueryValueEx \"%s\" failed. Error = %ld", key, GetLastError());
      RegCloseKey(key);
      return -1;
   }

   RegCloseKey(key);
   return 0;
}


/*! Open TAP driver. */
int win_open_tun(char *dev, int s)
{
   char deviceId[SIZE_256], deviceName[SIZE_256], tapPath[SIZE_256];
   TapData_t *tapData = &tapData_;
   DWORD len = 0;
   int status, i;

   for (i = 0; tap_component_id_[i] != NULL; i++)
      if ((status = findTapDevice(deviceId, sizeof(deviceId), deviceName, sizeof(deviceName), tap_component_id_[i])) != -1)
         break;

   if (status == -1)
   {
      log_msg(LOG_ALERT, "could not find TAP driver with valid componentId. Probly not installed");
      return -1;
   }

   log_debug("TAP found. deviceId = \"%s\", deviceName = \"%s\"", deviceId, deviceName);

   snprintf(tapPath, sizeof(tapPath), "%s%s%s", USERMODEDEVICEDIR, deviceId, TAPSUFFIX);
   log_debug("creating file at \"%s\"", tapPath);
   tapData->fd = CreateFile( tapPath, GENERIC_READ | GENERIC_WRITE, 0, 0,
         OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0 );   
    
   if (tapData->fd == INVALID_HANDLE_VALUE)
   {
      log_msg(LOG_ALERT, "CreateFile failed. Error = %ld", GetLastError());
      return -1;
   }

   status = TRUE;
   // FIXME: return value should be handled!
   DeviceIoControl(tapData->fd, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof
         (status), &status, sizeof (status), &len, NULL);

   // FIXME: return value should be handled!
   tapData->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
   // FIXME: return value should be handled!
   tapData->write_event = CreateEvent(NULL, FALSE, FALSE, NULL);

   tapData->read_overlapped.Offset = 0;
   tapData->read_overlapped.OffsetHigh = 0;
   tapData->read_overlapped.hEvent = tapData->read_event;

   tapData->write_overlapped.Offset = 0;
   tapData->write_overlapped.OffsetHigh = 0;
   tapData->write_overlapped.hEvent = tapData->write_event;

   // set IPv6 address
   // % netsh interface ipv6 add address "LAN-Verbindung 2" fd87:d87e:eb43:0:84:2100:0:8421 
   // add route
   // % netsh interface ipv6 add route  fd87:d87e:eb43::/48 "LAN-Verbindung 2"

   strlcpy(dev, deviceName, s);
   return 0;
}


/*! Close TAP driver. */
int win_close_tun(void)
{
   if (!CloseHandle(tapData_.fd))
   {
      log_msg(LOG_ERR, "CloseHandle failed. Error = %ld", GetLastError());
      return -1;
   }
   return 0;
}


int win_write_tun(const char *jb, int len)
{
   TapData_t *tapData = &tapData_;
   DWORD written, err;

   log_debug("WriteFile %d bytes", len);
   if (!WriteFile(tapData->fd, jb, len, &written, &tapData->write_overlapped))
   {
      if ((err = GetLastError()) != ERROR_IO_PENDING)
      {   
         log_msg(LOG_ERR, "error writing %ld", err);
         return -1;
      }
      else
      {
         log_debug("IO_PENDING");
         if (!GetOverlappedResult(tapData->fd, &tapData->write_overlapped, &written, FALSE))
         {
            err = GetLastError();
            log_debug("GetOverlappedResult failed. Error = %ld", err);
            if (err == ERROR_IO_INCOMPLETE)
            {
               log_debug("IO_COMPLETE, WaitForSingleObject");
               if ((err = WaitForSingleObject(tapData->write_event, INFINITE)) == WAIT_FAILED)
                  log_msg(LOG_ERR, "WaitForSingleObject failed. Error = %ld", GetLastError());
               else
                  log_debug("WaitForSingleObject returen %08lx", err);
            }
            written = -1;
         }
         log_debug("GetOverlappedResult(): written = %d", written);
      }
   }

   return written;
}


/*! Read from TAP driver. */
int win_read_tun(char *buf, int n)
{
   TapData_t *tapData = &tapData_;
   DWORD len, err;
    
   log_debug("ReadFile max. %d bytes", n);
   if (!ReadFile(tapData->fd, buf, n, &len, &tapData->read_overlapped))
   {
      // check if I/O is still pending
      if ((err = GetLastError()) == ERROR_IO_PENDING)
      {
         for (err = WAIT_TIMEOUT; err == WAIT_TIMEOUT;)
         {
            log_debug("ReadFile pending...");
            if ((err = WaitForSingleObject(tapData->read_event, SELECT_TIMEOUT * 1000)) == WAIT_FAILED)
               log_msg(LOG_ERR, "WaitForSingleObject failed. Error = %ld", GetLastError());
            log_debug("WaitForSingleObject returned %08lx", err);
         }

         if (!GetOverlappedResult(tapData->fd, &tapData->read_overlapped, &len, FALSE))
         {
            // GetOverlappedResult may fail if buffer was too small
            err = GetLastError();
            if (err == ERROR_IO_INCOMPLETE)
               log_msg(LOG_WARNING, "GetOverlappedResult return INCOMPLETE...unhandled");
            else
               log_msg(LOG_WARNING, "GetOverlappedResult failed. Error = %ld", err);
         }
         else
            log_debug("overlapped_read returned %ld bytes", len);
      }
      else
         log_debug("ReadFile returned %ld bytes", err);
   }

   return len;
}

#if 0
#define BUFLEN 1500
int main()
{
   char buf[BUFLEN];
   int len, i;

   memset(&tapData_, 0, sizeof(tapData_));

   win_open_tun();
   printf("opened....");

   //win_write_tun(buf, 10);
   for (;;)
   {
   len = win_read_tun(buf, BUFLEN);

   printf("read %d bytes\n", len);
   for (i = 0; i < len; i++)
      printf("%02x ", buf[i] & 0xff);
   printf("\n\n");
   }

   win_close_tun();



   return 0;
}
#endif

#endif /* __CYGWIN__ */

