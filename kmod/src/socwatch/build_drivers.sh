#!/bin/bash
# Helper script to build both socwatch and socperf drivers
# and sign them in the case of Android targets. Script must
# executed in the top-level directory of SoCWatch package.
# **********************************************************************************
#  This file is provided under a dual BSD/GPLv2 license.  When using or
#  redistributing this file, you may do so under either license.

#  GPL LICENSE SUMMARY

#  Copyright(c) 2015 - 2019 Intel Corporation.

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of version 2 of the GNU General Public License as
#  published by the Free Software Foundation.

#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.

#  Contact Information:
#  SoC Watch Developer Team <socwatchdevelopers@intel.com>
#  Intel Corporation,
#  1906 Fox Drive,
#  Champaign, IL 61820

#  BSD LICENSE

#  Copyright(c) 2015 - 2019 Intel Corporation.

#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:

#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.

#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# **********************************************************************************
DO_LINUX=0
BUILD_SOCPERF=1
BUILD_HYPERVISOR=0
HYPERVISOR_SUPPORTED=0
OPTIONS=""
SOCWATCH_DRIVER_SRC=socwatch_driver
SOCWATCH_DRIVER=socwatch2_10.ko
SOCPERF_DRIVER_SRC=soc_perf_driver/src
SOCPERF_DRIVER=socperf3.ko
IS_SOCPERF_BUILT=false
HYPERVISOR_DRIVER_SRC=hypervisor_driver
HYPERVISOR_DRIVER=socwatchhv2_0.ko
ERROR_FILE=""
ERROR_OCCURRED=false
PRIV_SIGNING_KEY=signing_key.priv
PEM_SIGNING_KEY=signing_key.pem
X509_SIGNING_KEY=signing_key.x509
SIGN_FILE="X"
C_COMPILER="X"
DEFAULT_C_COMPILER=gcc
HYPERVISOR_NAME="X";

error()
{
    local message=$1
    echo "ERROR: $message"
    echo "ERROR: $message" >> ${ERROR_FILE}
    ERROR_OCCURRED=true
}

sign_driver()
{
    local sign_file=$1
    local unsigned_driver=$2
    local signed_driver=$3
    local priv_pem_key_path="${KERNEL_BUILD_DIR}/certs/${PEM_SIGNING_KEY}"
    local x509_key_path="${KERNEL_BUILD_DIR}/certs/${X509_SIGNING_KEY}"

    if ([ ! -r ${priv_pem_key_path} ] || [ ! -r ${x509_key_path} ]); then
        priv_pem_key_path="${KERNEL_BUILD_DIR}/${PRIV_SIGNING_KEY}"
        x509_key_path="${KERNEL_BUILD_DIR}/${X509_SIGNING_KEY}"
    fi

    if ([ ! -r ${priv_pem_key_path} ] || [ ! -r ${x509_key_path} ]); then
        error "The kernel build directory does not have signing keys ${PEM_SIGNING_KEY} (or ${PRIV_SIGNING_KEY}) and ${X509_SIGNING_KEY}. Drivers will not be signed."
        error "Please check if the target's kernel requires drivers to be signed."
    else
        ${sign_file} sha256 ${priv_pem_key_path} ${x509_key_path} ${unsigned_driver} ${signed_driver}
        if [ $? -ne 0 ]; then
            echo "Failed to sign the driver"
        fi
    fi
}

build_driver()
{
    # 1. Build driver
    # 2. Sign driver if requested
    # 3. Copy the driver to TARGET_DIR
    local driver_name=$1
    local options="${@:2}"
    echo ${options}
    echo "************ Building ${driver_name} driver ************"

    local build_Driver_script=""
    if [ ${driver_name} == ${SOCPERF_DRIVER} ]; then
        build_driver_script=build-driver
        IS_SOCPERF_BUILT=true
    else
        # Sofia and SoCWatch drivers
        build_driver_script=build_linux_driver.sh
        ./${build_driver_script} ${options} --clean
    fi

    ./${build_driver_script} ${options}
    local retVal=$?;
    if [ $retVal -ne 0 ]; then
        error "Failed to build ${driver_name} driver"
        if [ ${driver_name} == ${SOCPERF_DRIVER} ]; then
            IS_SOCPERF_BUILT=false
        fi
        return
    fi

    local signing_error=0
    if [ "${SIGN_FILE}" != "X" ]; then
        if [ -x "${SIGN_FILE}" ]; then
            echo "************ Signing ${driver_name} driver using ${SIGN_FILE} ************"
            mv ${driver_name} ${driver_name}.unsigned
            sign_driver ${SIGN_FILE} ${driver_name}.unsigned ${driver_name}
            if [ $? -ne 0 ]; then
                signing_error=1
            fi
            rm -f ${driver_name}.unsigned
        else
            echo "Signing file ${SIGN_FILE} is invalid"
            signing_error=1
        fi

        if [ ${signing_error} -eq 1 ]; then
            local sign_file=${KERNEL_BUILD_DIR}/scripts/sign-file
            echo "Attempting to sign the drivers with kernel source sign_file: ${sign_file}"
            if [ -x "${sign_file}" ]; then
                echo "************ Signing ${driver_name} driver using ${sign_file} ************"
                mv ${driver_name} ${driver_name}.unsigned
                sign_driver ${sign_file} ${driver_name}.unsigned ${driver_name}
                if [ $? -ne 0 ]; then
                    signing_error=0
                fi
                rm -f ${driver_name}.unsigned
            else
                echo "Signing file ${sign_file} is invalid"
                signing_error=1
            fi
        fi
    fi

    if [ ${signing_error} -eq 1 ]; then
        error "Failed to sign the driver"
    else
        if [ ! -f ./"$driver_name" ]; then
            # To identify a mismatch in generated vs script version of the driver
            echo ""
            error "Failed to find ${driver_name} driver in current directory : `pwd`"
            echo ""
        else
            mv ${driver_name} ${TARGET_DIR}/${driver_name}
        fi
    fi
}


do_work()
{
    TARGET_DIR=${top_dir}/drivers

    # Move all the built and signed drivers to a separate directory
    rm -rf ${TARGET_DIR}
    mkdir ${TARGET_DIR}

    if [ $BUILD_SOCPERF -eq 1 ]; then
        # Build socperf driver if requested
        cd ${SOCPERF_DRIVER_SRC}

        if [ "$C_COMPILER" = "X" ]; then
            OPTIONS="-ni";
        else
            OPTIONS="-ni --c-compiler=$C_COMPILER"
        fi

        if [ -n "$KERNEL_BUILD_DIR" ]; then
            OPTIONS="$OPTIONS --kernel-src-dir=${KERNEL_BUILD_DIR}"
        fi

        if [ -n "$MAKE_ARGS" ]; then
            OPTIONS="$OPTIONS --make-args=\"${MAKE_ARGS}\""
        fi

        build_driver ${SOCPERF_DRIVER} ${OPTIONS}
        cd ${top_dir}
    fi

    # Build socwatch driver
    cd ${SOCWATCH_DRIVER_SRC}

    if [ "$C_COMPILER" = "X" ]; then
        OPTIONS="";
    else
        OPTIONS="-c $C_COMPILER"
    fi

    if [ $DO_LINUX -eq 1 ]; then
        OPTIONS="$OPTIONS -l"
    fi

    if [ -n "$KERNEL_BUILD_DIR" ]; then
        OPTIONS="$OPTIONS -k ${KERNEL_BUILD_DIR}"
    fi

    if [ ${IS_SOCPERF_BUILT} == "true" ]; then
        OPTIONS="$OPTIONS -s ${top_dir}/${SOCPERF_DRIVER_SRC}/Module.symvers"
    fi

    if [ -n "$MAKE_ARGS" ]; then
        OPTIONS="$OPTIONS --make-args \"${MAKE_ARGS}\""
    fi

    echo "$OPTIONS will be used to build the SoCWatch driver"
    build_driver ${SOCWATCH_DRIVER} ${OPTIONS}
    cd ${top_dir}

    if [ ${BUILD_HYPERVISOR} -eq 1 ]; then
        cd ${HYPERVISOR_DRIVER_SRC}
        OPTIONS="-k ${KERNEL_BUILD_DIR} --hypervisor ${HYPERVISOR_NAME}"
        build_driver ${HYPERVISOR_DRIVER} ${OPTIONS}
        cd ${top_dir}
    fi

    if [ ${ERROR_OCCURRED} == "true" ]; then
        echo ""
        echo "****** Errors occurred. Please check ${ERROR_FILE} for errors and the stderr/stdout for more information ******"
        echo ""
        exit 1
    fi
    # Moved this message here to make sure no errors occured
    echo "************ Built drivers are copied to ${TARGET_DIR} directory ************"
}

usage()
{
    echo "Usage: sh $(basename $0) [options]";
    echo "Where options are:"
    echo "-h: Print this help/usage message";
    echo "-c, --c-compiler [Path to c compiler]: Specify an alternate compiler; default is $DEFAULT_C_COMPILER"
    echo "-k, --kernel-build-dir [path]:"
    echo "                              Specify the path to the kernel build directory."
    echo "                              Required for Android and Chrome targets";
    echo "-l: Build drivers for Linux target";
    echo "-n: Socperf driver will not be built";
    echo "-s, --sign-file [path]: Specify the path to the sign-file for"
    echo "                        the target Android OS image (Optional; required for older versions of Android).";
    echo "--make-args: extra arguments to pass to make command"
    if [ $HYPERVISOR_SUPPORTED -eq 1 ]; then
        echo "--hypervisor [mobilevisor|acrn]: Build drivers for the specified hypervisor";
    fi
}

get_args()
{
    while [ $# -gt 0 ]; do
        case $1 in
            -h)
                usage;
                exit 0;;
            -k | --kernel-build-dir)
                KERNEL_BUILD_DIR=$2;
                shift;
                if [ ! -d "${KERNEL_BUILD_DIR}" ]; then
                    echo "Please provide a valid kernel build directory for the target"
                    exit 1;
                fi
                echo "${KERNEL_BUILD_DIR} will be used as the kernel build directory"
                ;;
            -s | --sign-file)
                SIGN_FILE=$2;
                if [ -f "${SIGN_FILE}" ]; then
                    shift;
                    if [ ! -x "${SIGN_FILE}" ]; then
                        echo "************ The signing file provided is not valid. Signing will be attempted with the sign-file in the kernel source directory if found. ************"
                    fi
                fi
                ;;
            --hypervisor)
                if [ ${HYPERVISOR_SUPPORTED} -eq 1 ]; then
                    BUILD_HYPERVISOR=1;
                else
                    echo "Hypervisor support is not available";
                    exit 1;
                fi
                HYPERVISOR_NAME=$2;
                echo "Building drivers for hypervisor '$HYPERVISOR_NAME'"
                shift;;
            -l)
                echo "Building drivers for Linux target"
                DO_LINUX=1;;
            -n)
                echo "Socperf driver will not be built"
                BUILD_SOCPERF=0;;
            -c | --c-compiler)
                C_COMPILER=$2; shift;;
            --make-args)
                MAKE_ARGS=$2;
                echo "Using extra make arguments $MAKE_ARGS"
                shift;;
            *)
                usage; exit 1;;
        esac
        shift;
    done
}

main()
{
    if [ -d "$HYPERVISOR_DRIVER_SRC" ]; then
        HYPERVISOR_SUPPORTED=1;
    fi

    local top_dir=`pwd`
    # Record errors in a file
    ERROR_FILE=${top_dir}/driver_build_errors.txt
    rm -f ${ERROR_FILE}

    get_args $*
    do_work
}

main $*
