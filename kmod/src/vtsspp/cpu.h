/*
  Copyright (C) 2018-2019 Intel Corporation.  All Rights Reserved.

  This file is part of SEP Development Kit

  SEP Development Kit is free software; you can redistribute it
  and/or modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  SEP Development Kit is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with SEP Development Kit; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

  As a special exception, you may use this file as part of a free software
  library without restriction.  Specifically, if other files instantiate
  templates or use macros or inline functions from this file, or you compile
  this file and link it with other files to produce an executable, this
  file does not by itself cause the resulting executable to be covered by
  the GNU General Public License.  This exception does not however
  invalidate any other reasons why the executable file might be covered by
  the GNU General Public License.
*/
#ifndef _VTSS_CPU_H_
#define _VTSS_CPU_H_

#define VTSS_FAM_P4      0x0f
#define VTSS_FAM_P6      0x06

#define VTSS_CPU_MRM     0x0f
#define VTSS_CPU_PNR     0x17
#define VTSS_CPU_DNG     0x1d

#define VTSS_CPU_NHM     0x1e
#define VTSS_CPU_NHM_G   0x1f
#define VTSS_CPU_NHM_EP  0x1a
#define VTSS_CPU_NHM_EX  0x2e

#define VTSS_CPU_WMR     0x25
#define VTSS_CPU_WMR_EP  0x2c
#define VTSS_CPU_WMR_EX  0x2f

#define VTSS_CPU_SNB     0x2a
#define VTSS_CPU_SNB_X   0x2d
#define VTSS_CPU_IVB     0x3a
#define VTSS_CPU_IVB_X   0x3e

#define VTSS_CPU_HSW     0x3c
#define VTSS_CPU_HSW_X   0x3f
#define VTSS_CPU_HSW_ULT 0x45
#define VTSS_CPU_HSW_GT3 0x46

#define VTSS_CPU_BDW     0x3d
#define VTSS_CPU_BDW_GT3 0x47
#define VTSS_CPU_BDW_X   0x4f
#define VTSS_CPU_BDW_XD  0x56

#define VTSS_CPU_SKL    0x5e
#define VTSS_CPU_SKL_M  0x4e
#define VTSS_CPU_SKL_X  0x55

#define VTSS_CPU_KBL    0x9e
#define VTSS_CPU_KBL_M  0x8e

#define VTSS_CPU_CNL    0x42
#define VTSS_CPU_CNL_M  0x66

#define VTSS_CPU_ICL_M  0x7e
#define VTSS_CPU_ICL_X  0x6c
#define VTSS_CPU_ICL_XD 0x6a

#define VTSS_CPU_KNL    0x57
#define VTSS_CPU_KNM    0x85

#define VTSS_CPU_ATOM_BNL   0x1c
#define VTSS_CPU_ATOM_SLW_T 0x35
#define VTSS_CPU_ATOM_SLW   0x36

#define VTSS_CPU_ATOM_GLM   0x5c
#define VTSS_CPU_ATOM_DNV   0x5f
#define VTSS_CPU_ATOM_GLP   0x7a

#endif
