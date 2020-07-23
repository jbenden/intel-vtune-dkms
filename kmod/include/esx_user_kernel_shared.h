/****
 * -------------------------------------------------------------------------
 *               INTEL CORPORATION PROPRIETARY INFORMATION
 *  This software is supplied under the terms of the accompanying license
 *  agreement or nondisclosure agreement with Intel Corporation and may not
 *  be copied or disclosed except in accordance with the terms of that
 *  agreement.
 *        Copyright (C) 2019 Intel Corporation.  All Rights Reserved.
 * -------------------------------------------------------------------------
****/

/*
    Description:    Definitions shared between EMON ESX Managment User and
                    Kernel.
*/

#ifndef _ESXUSERKERNELSHARED_H_
#define _ESXUSERKERNELSHARED_H_

#include "vmkapi.h"
#include "lwpmudrv_defines.h"
#include "lwpmudrv_version.h"
#include "lwpmudrv_ioctl.h"


//Total number of callbacks

#define NUM_CALLBACKS 1


//Name used to describe this interface

#define INTERFACE_NAME "Intel-EMON-Mgmt"


//Vendor of this interface

#define INTERFACE_VENDOR "Intel"

/*
 * Each callback must have a unique 64-bit integer identifier.
 * The identifiers 0 through VMK_MGMT_RESERVED_CALLBACKS
 * are reserved and must not be used by consumers of the
 * management APIs.  Here, we declare two callback
 * identifiers - one each for the kernel and user callbacks.
 * These identifiers are used by consumers of the API at
 * runtime to invoke the associated callback.
 *
 */


#define EMON_CB_TO_KERNEL     (VMK_MGMT_RESERVED_CALLBACKS + 1)
#define EMON_CB_TO_USER       (VMK_MGMT_RESERVED_CALLBACKS + 2)

#ifdef VMKERNEL

/*
 * These are the definitions of prototypes as viewed from
 * kernel-facing code. Kernel callbacks have their prototypes
 * defined. User callbacks, in this section, will be
 * #define'd as NULL, since their callback pointer has no
 * meaning from the kernel perspective.
 *
 * All callbacks must return an integer, and must take two
 * metadata parameters.  User callbacks take two vmk_uint64
 * paramaters as the first two arguments.	The first argument is
 * the cookie value, and the second is an instance ID from which
 * the callback originated in the kernel.	Kernel callbacks take
 * a vmk_MgmtCookies pointer as the first parameter and a
 * vmk_MgmtEnvelope pointer as the second parameter.  The cookies
 * structure contains handle-wide and session-specific cookie
 * values.  The envelope structure contains a session ID (indicating
 * which session the callback request originated from) and an
 * instance ID (indicating which specific instance, if any, this
 * callback is destined for).	When not addressing specific instances
 * or tracking instance-specific callback invocations, simply use
 * VMK_MGMT_NO_INSTANCE_ID for this parameter.  Regarding session IDs,
 * kernel management handles support simultaneous access by user-space
 * applications, thus the callbacks convey more information about which
 * session the callback invocation is associated with.  The return type merely
 * indicates that the callback ran to completion without
 * error - it does not indicate the semantic success or failure
 * of the operation.  The cookie argument passed to the callback
 * is the same value that was given as the 'cookie' parameter
 * during initialization.	Thus kernel callbacks get a handle cookie
 * provided to vmk_MgmtInit() (in addition to the session-specific cookie
 * that a kernel module may set in its session-announcement function), and
 * provided to vmk_MgmtUserInit().  The instanceId corresponds
 * to the specific instance that this callback is targeted to
 * (if it's a kernel-located callback) or the instance from
 * which the callback originates (if it's a user-located callback).
 *
 */

#define LWPMUDRV_User_Callback NULL


int LWPMUDRV_Kernel_Callback (
    vmk_MgmtCookies  *cookies,    //IN
    vmk_MgmtEnvelope *envelope,  // IN
    unsigned int     *cmd,      // IN
    IOCTL_ARGS_NODE  *args);   // IN/OUT

#else

/*
 * This section is where callback definitions, as visible to
 * user-space, go.  In this example, there are is one user-run
 * callback: testUserCallback.
 *
 * This callback takes two payload parameters: eventCount
 * and statParm.  The semantics of the buffers used for
 * eventCount and statParm are determined by the individual
 * parameter type, as specified in the vmk_MgmtCallbackInfo
 * corresponding to this callback.  In the case of user-running
 * callbacks (which this is), all callbacks are asynchronous
 * and therefore all parameters can only be of the type
 * VMK_MGMT_PARMTYPE_IN.  This means that any changes by
 * testUserCallback to the buffers used for those parameters
 * will not be reflected in the kernel.
 */
#define LWPMUDRV_User_Callback     NULL

/*
  * Kernel-run callbacks are defined as NULL for the user-
  * compiled portion of the interface.
  */
#define LWPMUDRV_Kernel_Callback NULL

#endif /* VMKERNEL */



/*
 * Statically define and initialize the array of vmk_MgmtCallbackInfo
 * structures that fully describe
 * all of the callbacks that the management interface we're
 * using could invoke.  The array will include both user and
 * kernel callback descriptions.
 *
 * We also statically define and initialize the management
 * signature, which includes the callbacks.
 *
 * This file is intended to be compiled for both user-space
 * and kernel-space builds.
 */

vmk_MgmtCallbackInfo mgmtCallbacks[NUM_CALLBACKS] = {
   /*
    * The order of the callbacks in this array does not matter.
    * Here, we're enumerating the kernel space callback first.
    */
    {
      /*
       * The 'location' describes where this callback will run.
       */
    .location = VMK_MGMT_CALLBACK_KERNEL,
      /*
       * The 'callback' is the function that will be invoked.
       * This value may be a "don't care" if this file is being
       * compiled for user-space but the callback is a kernel
       * callback (or vice versa).  mgmtInterface.h conditionally
       * defines this.
       */
    .callback = LWPMUDRV_Kernel_Callback,
      /*
       * The 'synchronous' identifier indicates whether the callback
       * will be invoked synchronously from the caller, or whether
       * the callback is queued for later execution.  Notice that
       * only VMK_MGMT_CALLBACK_KERNEL callbacks can be synchronous.
       * Further, if your callback contains VMK_MGMT_PARMTYPE_OUT
       * or VMK_MGMT_PARMTYPE_INOUT parameters, your callback MUST
       * be synchronous (and thus must be a kernel callback).
       */
    .synchronous = 1, /* 0 indicates asynchronous */
      /*
       * 'numParms' indicates the number of non-cookie, non-instanceId parameters
       * that the callback accepts.  In this case, the callback takes
       * two parameters in addition to the cookie and instanceId, so 'numParms' is 2.
       * 'numParms' must be less than or equal to
       * VMK_MGMT_MAX_CALLBACK_PARMS.
       */
    .numParms = 2,
       /*
        * 'parmSizes' is an array indicating the size, in bytes, of each
        * non-cookie and non-instanceId parameter.  The array is in the order of the
        * parameters that the callback takes (after the instanceId).
        */
    .parmSizes = {sizeof(unsigned int),
                  sizeof(IOCTL_ARGS_NODE)
                 },
	  /*
	   * 'parmTypes' is an array indicating how memory buffers carrying
	   * the contents of the parameters to the callback should be treated.
		* There are three types:
		* VMK_MGMT_PARMTYPE_IN    -- an input parameter to the callback.
		* VMK_MGMT_PARMTYPE_OUT   -- an output parameter from the callback.
		* VMK_MGMT_PARMTYPE_INOUT -- a parameter that is both an input
		*							  to the callback and an output from it.
		* VMK_MGMT_PARMTYPE_IN parameters are copied from the caller into
		* a temporary buffer that is prepared prior to invoking the callback.
		* VMK_MGMT_PARMTYPE_OUT parameters give a scratch buffer as input
		* to the callback but then are copied back to the caller after the
		* callback is completed.
		* VMK_MGMT_PARMTYPE_INOUT parameters are copied from the caller into
		* a temporary buffer before the callback is invoked, then the
		* callback is invoked, and then the contents of the temporary buffer
		* (presumably modified by the callback) is copied back to the caller.
		* NOTE:  In ALL cases, the contents of the buffers passed to the
		*		  callbacks are invalid after the callback has completed
		*		  execution.
		* NOTE:  VMK_MGMT_PARMTYPE_OUT and VMK_MGMT_PARMTYPE_INOUT parameters
		*		  require synchronous execution, and thus they can only be
		*		  used for VMK_MGMT_CALLBACK_KERNEL callbacks.
		*/

    .parmTypes = {VMK_MGMT_PARMTYPE_IN,
                  VMK_MGMT_PARMTYPE_INOUT
                 },
      /*
       * 'callbackId' must be unique among all callback IDs registered with
       * a given Management API signature.  It may not be any of the numbers
       * 0 through VMK_MGMT_RESERVED_CALLBACKS, inclusive.
       */
    .callbackId = EMON_CB_TO_KERNEL,
    },
};

/*
 * The Management API Signature is used to define the overall signature of the
 * management interface that will be used.  It contains a name, vendor, version,
 * and a description of the callbacks that the interface contains.
 */
vmk_MgmtApiSignature lwpmudrv_mgmt_sig = {
    .version       = VMK_REVISION_FROM_NUMBERS(1,0,0,0),
    .name.string   = INTERFACE_NAME,
    .vendor.string = INTERFACE_VENDOR,
    .numCallbacks  = NUM_CALLBACKS,
    .callbacks     = mgmtCallbacks,
};
#endif /* _ESXUSERKERNELSHARED_H_ */
