/*
  Copyright (C) 2010-2019 Intel Corporation.  All Rights Reserved.

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
#ifndef _VTSS_BTS_H_
#define _VTSS_BTS_H_

#include "config.h"

#include <linux/sched.h>        /* for struct task_struct */

#define VTSS_BTS_MIN  16
#define VTSS_BTS_MAX  320

typedef union
{
    struct {
        void *branch_from;
        void *branch_to;
        void *prediction;
    } v64;

    struct {
        void *branch_from;
        void *branch_pad0;
        void *branch_to;
        void *branch_pad1;
        void *prediction;
        void *branch_pad2;
    } v32;
} vtss_bts_t;

int  vtss_bts_init(int brcount);
void vtss_bts_fini(void);
void vtss_bts_init_dsa(void);
void vtss_bts_enable(void);
void vtss_bts_disable(void);
int  vtss_bts_overflowed(int cpu);
unsigned short vtss_bts_dump(unsigned char *bts_buff);

#endif /* _VTSS_BTS_H_ */
