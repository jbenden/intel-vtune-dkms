#!/usr/bin/python2


#     Copyright(C) 2016-2018 Intel Corporation.  All Rights Reserved.

#     This file is part of SEP Development Kit

#     SEP Development Kit is free software; you can redistribute it
#     and/or modify it under the terms of the GNU General Public License
#     version 2 as published by the Free Software Foundation.

#     SEP Development Kit is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.

#     You should have received a copy of the GNU General Public License
#     along with SEP Development Kit; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

#     As a special exception, you may use this file as part of a free software
#     library without restriction.  Specifically, if other files instantiate
#     templates or use macros or inline functions from this file, or you compile
#     this file and link it with other files to produce an executable, this
#     file does not by itself cause the resulting executable to be covered by
#     the GNU General Public License.  This exception does not however
#     invalidate any other reasons why the executable file might be covered by
#     the GNU General Public License.


import struct
import os
import sys

DMI_FILENAME = "/sys/firmware/dmi/entries/{0}/raw"
DMI_GROUP_ASSOCIATIONS_TYPE = "14-{0}"
DMI_GROUP_STRING = "Group: "
DMI_SYS_GROUP_NAME = "Knights Landing Information"
DMI_SYS_GENERAL_INFO_TYPE = "{0}-0"


def read_dmi_info():
    type_file_num = 0
    while True:
        if process_dmi_group_file(DMI_FILENAME.format(DMI_GROUP_ASSOCIATIONS_TYPE.format(type_file_num))) == 1:
            type_file_num += 1
        else:
            break

def process_dmi_group_file(filename):
    fd = None
    try:
        if not os.path.isfile(filename):
            return 2
        f = os.popen("strings {}".format(filename))
        if DMI_SYS_GROUP_NAME not in f.read():
            return 1

        fd = os.open(filename, os.O_RDONLY)
        length = struct.unpack('1B', os.read(fd, 1))[0]
        os.lseek(fd, length, os.SEEK_SET)
        name_str = os.read(fd, (len(DMI_GROUP_STRING) + len(DMI_SYS_GROUP_NAME)))
        if DMI_SYS_GROUP_NAME not in name_str:
            return 1
        members = (length - 5) / 3
        os.lseek(fd, 5, os.SEEK_SET)
        for x in range(0, members):
            grp_type = struct.unpack('1B', os.read(fd, 1))[0]
            grp_handle = struct.unpack('1H', os.read(fd, 2))[0]
            if process_dmi_member_file(DMI_FILENAME.format(DMI_SYS_GENERAL_INFO_TYPE.format(grp_type))) == 0:
                break
    except OSError as e:
        sys.stderr.write("Information not found on DMI sysfs: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting information from DMI sysfs: {0}\n".format(sys.exc_info()[0]))
        return 2
    finally:
        if fd:
            os.close(fd)
    return 0

def get_memory_mode(mem_mode):
    #print(mem_mode)
    switcher = {
        1: "Cache",
        2: "Flat",
        4: "Hybrid",
    } 
    return switcher.get(mem_mode, "None")


def get_cluster_mode(cluster_mode):
    #print(cluster_mode)
    switcher = {
        1:  "Quadrant",
        2:  "Hemisphere",
        4:  "SNC4",
        8:  "SNC2",
        16: "All2All",
    } 
    return switcher.get(cluster_mode, "None")


def process_dmi_member_file(filename):
    grp_fd = None
    try:
        grp_fd = os.open(filename, os.O_RDONLY)
        os.lseek(grp_fd, 4, os.SEEK_SET)
        member_id = struct.unpack('1B', os.read(grp_fd, 1))[0]
        if member_id != 0x0001:
            return 1
        os.lseek(grp_fd, 7, os.SEEK_SET)
        supported_cluster_mode = struct.unpack('1B', os.read(grp_fd, 1))[0]
        conf_cluster_mode = struct.unpack('1B', os.read(grp_fd, 1))[0]
        supported_memory_mode = struct.unpack('1B', os.read(grp_fd, 1))[0]
        conf_memory_mode = struct.unpack('1B', os.read(grp_fd, 1))[0]
        conf_MCDRAM_cache = struct.unpack('1B', os.read(grp_fd, 1))[0]
        cluster_mode = get_cluster_mode(conf_cluster_mode)
        memory_mode = get_memory_mode(conf_memory_mode)
        #print("SupportedClusterMode={}".format(bin(supported_cluster_mode)))
        print("ClusterMode={}".format(cluster_mode))
        #print("SupportedMemoryMode={}".format(bin(supported_memory_mode)))
        print("MemoryMode={}".format(memory_mode))
        print("MCDRAMCache={}".format(conf_MCDRAM_cache))
    except OSError as e:
        sys.stderr.write("Information not found on DMI sysfs: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting information from DMI sysfs: {0}\n".format(sys.exc_info()[0]))
        return 2
    finally:
        if grp_fd:
            os.close(grp_fd)
    return 0

##print("Reading DMI Information for KNL Configuration.")
ret_val = read_dmi_info()
##print("Finishing script.")
exit(ret_val)
