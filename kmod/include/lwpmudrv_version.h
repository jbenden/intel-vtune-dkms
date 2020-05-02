/****
 * -------------------------------------------------------------------------
 *               INTEL CORPORATION PROPRIETARY INFORMATION
 *  This software is supplied under the terms of the accompanying license
 *  agreement or nondisclosure agreement with Intel Corporation and may not
 *  be copied or disclosed except in accordance with the terms of that
 *  agreement.
 *        Copyright (C) 2010-2019 Intel Corporation.  All Rights Reserved.
 * -------------------------------------------------------------------------
****/
/*
 *  File  : lwpmudrv_version.h
 */

#ifndef _LWPMUDRV_VERSION_H_
#define _LWPMUDRV_VERSION_H_

#define _STRINGIFY(x)     #x
#define STRINGIFY(x)      _STRINGIFY(x)
#define _STRINGIFY_W(x)   L#x
#define STRINGIFY_W(x)    _STRINGIFY_W(x)

#define SEP_MAJOR_VERSION   5
#define SEP_MINOR_VERSION   10 
#define SEP_API_VERSION     2 // API version is independent of major/minor and tracks driver version

#define SEP_PREV_MAJOR_VERSION   5
#define EMON_PREV_MAJOR_VERSION  11

#define SEP_RELEASE_STRING  ""

#define EMON_MAJOR_VERSION          11
#define EMON_MINOR_VERSION          SEP_MINOR_VERSION
#define EMON_PRODUCT_RELEASE_STRING SEP_RELEASE_STRING

#if defined(SEP_ENABLE_PRIVATE_CPUS)
#define PRODUCT_TYPE      "private"
#define SEP_NAME          "sepint"
#define SEP_NAME_W        L"sepint"
#else
#if defined(SEP_ENABLE_NDA_CPUS)
#define PRODUCT_TYPE      "NDA"
#else
#define PRODUCT_TYPE      "public"
#endif
#define SEP_NAME          "sep"
#define SEP_NAME_W        L"sep"
#endif

#if !defined(PRODUCT_BUILDER)
#define PRODUCT_BUILDER unknown
#endif


#define TB_FILE_EXT       ".tb7"
#define TB_FILE_EXT_W     L".tb7"

#define SEP_PRODUCT_NAME  "Sampling Enabling Product"
#define EMON_PRODUCT_NAME "EMON"

#define PRODUCT_VERSION_DATE    __DATE__ " at " __TIME__

#define SEP_PRODUCT_COPYRIGHT  "Copyright(C) 2007-2019 Intel Corporation. All rights reserved."
#define EMON_PRODUCT_COPYRIGHT "Copyright(C) 1993-2019 Intel Corporation. All rights reserved."

#define PRODUCT_DISCLAIMER  "Warning: This computer program is protected under U.S. and international\ncopyright laws, and may only be used or copied in accordance with the terms\nof the license agreement.  Except as permitted by such license, no part\nof this computer program may be reproduced, stored in a retrieval system,\nor transmitted in any form or by any means without the express written consent\nof Intel Corporation."
#define PRODUCT_VERSION     STRINGIFY(SEP_MAJOR_VERSION)"."STRINGIFY(SEP_MINOR_VERSION)

#define SEP_MSG_PREFIX    SEP_NAME""STRINGIFY(SEP_MAJOR_VERSION)"_"STRINGIFY(SEP_MINOR_VERSION)":"
#define SEP_VERSION_STR   STRINGIFY(SEP_MAJOR_VERSION)"."STRINGIFY(SEP_MINOR_VERSION)

#if defined(DRV_OS_WINDOWS)

#define SEP_DRIVER_NAME   SEP_NAME"drv"STRINGIFY(SEP_MAJOR_VERSION)
#define SEP_DRIVER_NAME_W SEP_NAME_W L"drv" STRINGIFY_W(SEP_MAJOR_VERSION)
#define SEP_DEVICE_NAME   SEP_DRIVER_NAME

#define SEP_PREV_DRIVER_NAME   SEP_NAME"drv"STRINGIFY(SEP_PREV_MAJOR_VERSION)
#define SEP_PREV_DRIVER_NAME_W SEP_NAME_W L"drv" STRINGIFY_W(SEP_PREV_MAJOR_VERSION)
#define SEP_PREV_DEVICE_NAME   SEP_PREV_DRIVER_NAME

#endif

#if defined(DRV_OS_LINUX) || defined(DRV_OS_SOLARIS) || defined(DRV_OS_ANDROID) || defined(DRV_OS_FREEBSD)

#define SEP_DRIVER_NAME   SEP_NAME""STRINGIFY(SEP_MAJOR_VERSION)
#define SEP_SAMPLES_NAME  SEP_DRIVER_NAME"_s"
#define SEP_UNCORE_NAME   SEP_DRIVER_NAME"_u"
#define SEP_SIDEBAND_NAME SEP_DRIVER_NAME"_b"
#define SEP_EMON_NAME     SEP_DRIVER_NAME"_e"
#define SEP_DEVICE_NAME   "/dev/"SEP_DRIVER_NAME

#define SEP_PREV_DRIVER_NAME   SEP_NAME""STRINGIFY(SEP_PREV_MAJOR_VERSION)
#define SEP_PREV_SAMPLES_NAME  SEP_PREV_DRIVER_NAME"_s"
#define SEP_PREV_UNCORE_NAME   SEP_PREV_DRIVER_NAME"_u"
#define SEP_PREV_SIDEBAND_NAME SEP_PREV_DRIVER_NAME"_b"
#define SEP_PREV_DEVICE_NAME   "/dev/"SEP_PREV_DRIVER_NAME

#endif

#if defined(DRV_OS_MAC)

#define SEP_DRIVER_NAME   SEP_NAME""STRINGIFY(SEP_MAJOR_VERSION)
#define SEP_SAMPLES_NAME  SEP_DRIVER_NAME"_s"
#define SEP_DEVICE_NAME   SEP_DRIVER_NAME

#define SEP_PREV_DRIVER_NAME   SEP_NAME""STRINGIFY(SEP_PREV_MAJOR_VERSION)
#define SEP_PREV_SAMPLES_NAME  SEP_PREV_DRIVER_NAME"_s"
#define SEP_PREV_DEVICE_NAME   SEP_PREV_DRIVER_NAME

#endif

#endif
