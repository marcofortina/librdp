/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: privileged managed X11 session broker contract.
 * Invariants: all registry mutations are serialized, request workers are
 * bounded and session workloads execute only in dedicated supervisors.
 * Ownership: the broker owns its listener, worker threads and registry; live
 * persistent supervisors remain independent when the broker is stopped.
 * Threading: one accept thread and bounded request/monitor workers share the
 * registry through an internal mutex.
 * Trust boundary: Unix peer credentials, host-auth results, policy and session
 * tokens are all checked before a supervisor or registry entry is reached.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_BROKER_H
#define LIBRDP_X11_SERVER_MANAGED_BROKER_H

#include "server_managed_policy.h"

#include <librdp/librdp.h>

#include <stdint.h>

typedef struct x11_managed_broker x11_managed_broker;

x11_managed_broker* x11_managed_broker_new(
    const x11_managed_policy* policy,
    librdp_status* status);
void x11_managed_broker_free(x11_managed_broker* broker);
librdp_status x11_managed_broker_run(
    x11_managed_broker* broker);
librdp_status x11_managed_broker_cancel(
    x11_managed_broker* broker);
const char* x11_managed_broker_socket_path(
    const x11_managed_broker* broker);

#endif
