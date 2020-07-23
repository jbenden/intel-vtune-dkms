#!/bin/sh

VTUNE_AMPLIFIER_BASE="vtune_amplifier_"
VTUNE_AMPLIFIER_TARGET_BASE="vtune_amplifier_target_"
VTUNE_AMPLIFIER_SEP_TARGET_BASE="vtune_amplifier_target_sep_"

ALL_VTUNE_DRIVERS="all"
SEP_VTUNE_DRIVER="sep"

fatal() {
    >&2 echo "$1"
    exit 1
}

# == Env Check =================================================================
if [ -z "${UNPACK_DIR_path+x}" ] || [ -z "${BUILD_DIR_path+x}" ]; then
    fatal "Helper called in incorrect environment."
fi

# == Architecture ==============================================================
VTUNE_SUPPORTED_32_BIT="i386 i586 i686"
VTUNE_SUPPORTED_64_BIT="x86_64 amd64"

ARCHITECTURE_is_supported() {
    case " $VTUNE_SUPPORTED_32_BIT $VTUNE_SUPPORTED_64_BIT " in
        *" $VTUNE_TARGET_ARCH "*): ;;
        *) fatal "${SUMMARY} does not support ${TARGET_ARCH} architecture";;
    esac
}

ARCHITECTURE_package_get() {
    ARCHITECTURE_is_supported
    case " $VTUNE_SUPPORTED_64_BIT " in
        *" $VTUNE_TARGET_ARCH "*) echo "x86_64" ;;
        *) echo "x86" ;;
    esac
}

ARCHITECTURE_driver_get() {
    ARCHITECTURE_is_supported
    case " $VTUNE_SUPPORTED_64_BIT " in
        *" $VTUNE_TARGET_ARCH "*) echo "x32_64" ;;
        *) echo "x32" ;;
    esac
}

# == Package  ==================================================================
PACKAGE_archive_file_name() {
    ARCHITECTURE_package=$(ARCHITECTURE_package_get)

    if [ "$VTUNE_DRIVERS" = "$ALL_VTUNE_DRIVERS" ]; then
        echo "$VTUNE_AMPLIFIER_TARGET_BASE""$ARCHITECTURE_package"".tgz"
    elif [ "$VTUNE_DRIVERS" = "$SEP_VTUNE_DRIVER" ]; then
        echo "$VTUNE_AMPLIFIER_SEP_TARGET_BASE""$ARCHITECTURE_package"".tgz"
    else
        fatal "Incorrect type of VTune target package is chosen."
    fi
}

# == Kernel Configuration ======================================================
KERNEL_CONFIG_DIR=""
KERNEL_CONFIG_PATH=""

KERNEL_CONFIG_find() {
    KERNEL_CONFIG_DIR="$STAGING_KERNEL_BUILDDIR"
    KERNEL_CONFIG_PATH="$KERNEL_CONFIG_DIR/.config"

    [ -e "$KERNEL_CONFIG_PATH" ] && return

    KERNEL_CONFIG_DIR="$KBUILD_OUTPUT"
    KERNEL_CONFIG_PATH="$KERNEL_CONFIG_DIR/.config"

    [ -e "$KERNEL_CONFIG_PATH" ] && return

    fatal "Cannot find kernel .config file"
}

KERNEL_CONFIG_is_set() {
    grep -xqe "\\s*CONFIG_$1=y\\s*" "$KERNEL_CONFIG_PATH"
    return $?
}

KERNEL_CONFIG_set_or_module() {
    grep -xqe "\\s*CONFIG_$1=[y|m]\\s*" "$KERNEL_CONFIG_PATH"
    return $?
}

KERNEL_CONFIG_check() {
    KERNEL_CONFIG_find
    if [ "$VTUNE_DRIVERS" = "$ALL_VTUNE_DRIVERS" ]; then
        error_message=""
        if ! KERNEL_CONFIG_is_set 'SMP'; then
            error_message="CONFIG_SMP=y $error_message"
        fi
        if ! KERNEL_CONFIG_is_set 'MODULES'; then
            error_message="CONFIG_MODULES=y $error_message"
        fi
        if ! KERNEL_CONFIG_is_set 'MODULE_UNLOAD'; then
            error_message="CONFIG_MODULE_UNLOAD=y $error_message"
        fi
        if ! KERNEL_CONFIG_is_set 'KPROBES'; then
            error_message="CONFIG_KPROBES=y $error_message"
        fi
        if ! KERNEL_CONFIG_is_set 'RING_BUFFER'; then
            error_message="CONFIG_RING_BUFFER=y $error_message"
        fi
        if [ "$error_message" ]; then
            fatal "Cannot build VTSS driver because kernel missconfiguration. Please set $error_message or use 'vtune-sep-driver' target."
        fi
    elif [ "$VTUNE_DRIVERS" = "$SEP_VTUNE_DRIVER" ]; then
        :
    else
        fatal "Incorrect build type are chosen."
    fi
}

# == Build Script wrapper ======================================================
DRIVER_build() {
    KERNEL_CONFIG_check

    VTUNE_DRIVER_ARCH=$(ARCHITECTURE_driver_get)

    cd "$UNPACK_DIR_path/"*"/sepdk/src" || fatal "Cannot find driver sources."
    build_dir="$BUILD_DIR_path/$(basename "$(dirname "$(dirname "$(pwd)")")")"
    mkdir -p "$build_dir"

    build_script="$UNPACK_DIR_path/*/sepdk/src/build-driver"
    build_script=$(ls ${build_script})

    build_args=""
    build_args="$build_args -ni"
    build_args="$build_args --c-compiler=${VTUNE_CC}"
    build_args="$build_args --make-command=${VTUNE_MAKE}"
    build_args="$build_args --kernel-version=${KERNEL_VERSION}"
    build_args="$build_args --kernel-src-dir=${KERNEL_CONFIG_DIR}"
    build_args="$build_args --install-dir=${build_dir}"
    build_args="$build_args --make-args=PLATFORM=${VTUNE_DRIVER_ARCH}"

    if [ "$VTUNE_DRIVERS_PER_USER" = "y" ]; then
        build_args="$build_args --per-user"
    fi

    unset CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
    sh -x "${build_script}" $build_args
    return $?
}
