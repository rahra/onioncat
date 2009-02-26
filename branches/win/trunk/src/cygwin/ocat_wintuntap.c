/*
    Copyright 2008 Wolfgang Ginolas

    This file is part of P2PVPN.

    P2PVPN is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <objbase.h>
#include <winioctl.h>

//#include <jni.h>
//#include "org_p2pvpn_tuntap_TunTapWindows.h"


// this is the registry directory where the drivers reside in
#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
// this registry directory contains also information about network drivers
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
// I changed this from tap0801
#define TAP_COMPONENT_ID "tap0901"

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

// return: error?
int findTapDevice(char *deviceID, int deviceIDLen, char *deviceName, int deviceNameLen) {
    HKEY adapterKey;
    int i;
    LONG status;
    DWORD len;
    char keyI[1024];
    char keyName[1024];
    HKEY key;
    char componentId[256];
    
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapterKey);

    if (status != ERROR_SUCCESS) {
        printf("Could not open key '%s'!\n", ADAPTER_KEY);
        return 1;
    }

    //strncpy(deviceID, "", deviceIDLen);
    deviceID[0] = '\0';
    
    for (i=0;
            deviceID[0]=='\0' &&
            ERROR_SUCCESS==RegEnumKey(adapterKey, i, keyI, sizeof(keyI));
            i++) {
        //char componentId[256];
        
        snprintf(keyName, sizeof(keyName), "%s\\%s", ADAPTER_KEY, keyI);
printf("keyName %s\n", keyName);
        status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key);
        if (status != ERROR_SUCCESS) {
            printf("Could not open key '%s'!\n", keyName);
            return 1;
        }
        
        len = sizeof(componentId);
        status=RegQueryValueEx(key, "ComponentId", NULL, NULL, componentId, &len);
        if (status == ERROR_SUCCESS && strcmp(componentId, TAP_COMPONENT_ID)==0) {
            len = deviceIDLen;
            RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, deviceID, &len);
printf("devID %s\n", deviceID);
        }
printf("compID %s\n", componentId);

        RegCloseKey(key);
    }    
    
    RegCloseKey(adapterKey);

    if (deviceID[0]==0) return 1;
    
    snprintf(keyName, sizeof(keyName), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, deviceID);
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key);
    if (status!=ERROR_SUCCESS) return 1;

    len = deviceNameLen;
    status=RegQueryValueEx(key, "Name", NULL, NULL, deviceName, &len);
    RegCloseKey(key);
    if (status!=ERROR_SUCCESS) return 1;
    
    return 0;
}


#if 0
void setTapDataDev(JNIEnv *env, jobject this, TapData *tapData, char* dev) {
    jfieldID jfd, jdev; 
    jclass jclass; 
    jstring jstr;
    
    jclass = (*env)->GetObjectClass(env, this); 
    
    jfd = (*env)->GetFieldID(env, jclass, "cPtr", "J"); 
    (*env)->SetLongField(env, this, jfd , (jlong)tapData);
    
    jstr = (*env)->NewStringUTF(env, dev);
    jdev = (*env)->GetFieldID(env, jclass, "dev", "Ljava/lang/String;"); 
    (*env)->SetObjectField(env, this, jdev , jstr);
}

TapData *getTapData(JNIEnv *env, jobject this) {
    jfieldID jfd; 
    jclass jclass; 

    jclass = (*env)->GetObjectClass(env, this); 
    
    jfd = (*env)->GetFieldID(env, jclass, "cPtr", "J"); 
    return (TapData*)((*env)->GetLongField(env, this, jfd));
}

/*
 * Class:     org_p2pvpn_tuntap_TunTapWindows
 * Method:    openTun
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_p2pvpn_tuntap_TunTapWindows_openTun
  (JNIEnv * env, jobject this) {
#endif

int win_open_tun(void)
{
    char deviceId[256];
    char deviceName[256];
    char tapPath[256];
    TapData_t *tapData = &tapData_;
    unsigned long len = 0;
    int status;
    
    //tapData = malloc(sizeof(TapData));
    
    findTapDevice(deviceId, sizeof(deviceId), deviceName, sizeof(deviceName));
    printf("deviceID: '%s'\n", deviceId);
    printf("deviceName: '%s'\n", deviceName);
    
    snprintf(tapPath, sizeof(tapPath), "%s%s%s", USERMODEDEVICEDIR, deviceId, TAPSUFFIX);
printf("tapPath = %s\n", tapPath);    
    tapData->fd = CreateFile(
        tapPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        0 );   
    
    if (tapData->fd == INVALID_HANDLE_VALUE) {
        printf("Could not open '%s'!\n", tapPath);
        return 1;
    }

    status = TRUE;
    DeviceIoControl(tapData->fd, TAP_IOCTL_SET_MEDIA_STATUS,
                &status, sizeof (status),
                &status, sizeof (status), &len, NULL);

    tapData->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    tapData->write_event = CreateEvent(NULL, FALSE, FALSE, NULL);

    tapData->read_overlapped.Offset = 0;
    tapData->read_overlapped.OffsetHigh = 0;
    tapData->read_overlapped.hEvent = tapData->read_event;

    tapData->write_overlapped.Offset = 0;
    tapData->write_overlapped.OffsetHigh = 0;
    tapData->write_overlapped.hEvent = tapData->write_event;

    //setTapDataDev(env, this, tapData, deviceName);
    
    return 0;
}
#if 0
/*
 * Class:     org_p2pvpn_tuntap_TunTapWindows
 * Method:    close
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_p2pvpn_tuntap_TunTapWindows_close
  (JNIEnv *env , jobject this) {
    TapData *tapData;
#endif

int win_close_tun(void)
{
   if (!CloseHandle(tapData_.fd))
   {
      fprintf(stderr, "error closing handle");
      return -1;
   }
   return 0;
}

#if 0
/*
 * Class:     org_p2pvpn_tuntap_TunTapWindows
 * Method:    write
 * Signature: ([BI)V
 */
JNIEXPORT void JNICALL Java_org_p2pvpn_tuntap_TunTapWindows_write
  (JNIEnv *env , jobject this, jbyteArray jb, jint len) {
#endif

int win_write_tun(const char *jb, int len)
{
    TapData_t *tapData = &tapData_;
    //jbyte *b;
    DWORD written, err;
    BOOL result;
    
    //tapData = getTapData(env, this);
    //b = (*env)->GetByteArrayElements(env, jb, NULL);
    
    result = GetOverlappedResult(tapData->fd, &tapData->write_overlapped,
                                  &written, FALSE);

    if (!result && GetLastError() == ERROR_IO_INCOMPLETE)
        WaitForSingleObject(tapData->write_event, INFINITE);

    if (!WriteFile(tapData->fd, jb, len, &written, &tapData->write_overlapped))
    {
      if ((err = GetLastError()) != ERROR_IO_PENDING)
      {   
       fprintf(stderr, "error writing %ld \n", err);
       return -1;
      }
      else
         fprintf(stderr, "io pending\n");
    }

    return written;
    
    //(*env)->ReleaseByteArrayElements(env, jb, b, JNI_ABORT);
}
#if 0
/*
 * Class:     org_p2pvpn_tuntap_TunTapWindows
 * Method:    read
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_org_p2pvpn_tuntap_TunTapWindows_read
  (JNIEnv *env, jobject this, jbyteArray jb) {
#endif

int win_read_tun(char *buf, int n)
{
   TapData_t *tapData = &tapData_;
   DWORD len, err;
   BOOL result;
    
   if (!ReadFile(tapData->fd, buf, n, &len, &tapData->read_overlapped))
   {
      // check if I/O is still pending
      if ((err = GetLastError()) == ERROR_IO_PENDING)
      {
           printf("pending...\n");

         if ((err = WaitForSingleObject(tapData->read_event, INFINITE)) == WAIT_FAILED)
         {
            printf("wait failed %ld\n", GetLastError());
         }
         else
         {
            printf("wait returned: %08lx\n", err);
         }
         printf("len = %d\n");
         if (!GetOverlappedResult(tapData->fd, &tapData->read_overlapped, &len, FALSE))
         {
            // GetOverlappedResult may fail if buffer was too small
            err = GetLastError();
            if (err == ERROR_IO_INCOMPLETE)
               printf("INCOMPLETE\n");
            else
               printf("overlappedRes failed %ld\n", err);
         }
         else
            printf("read_overlapped = %ld\n", len);
      }
      else
         fprintf(stderr, "read err %ld\n", err);

   }
    
   return len;
}

#define BUFLEN 1500
int main()
{
   char buf[BUFLEN];
   int len, i;

   memset(&tapData_, 0, sizeof(tapData_));

   win_open_tun();
   printf("opened....");

   //win_write_tun(buf, 10);
   len = win_read_tun(buf, BUFLEN);

   printf("read %d bytes\n", len);
   for (i = 0; i < len; i++)
      printf("%02x ", buf[i]);

   sleep(10);
   win_close_tun();



   return 0;
}


