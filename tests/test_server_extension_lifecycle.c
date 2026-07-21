/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server extension-family lifecycle tests.
 * Coverage: timeout, cancellation, metrics retention and reconnect reset for
 * every public extension family.
 * Bug classes: stale pending work, cross-family state leakage, counter loss
 * before reconnect and generation reuse.
 * Determinism: the fixture contains no sockets, threads or external providers.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

#include "server/server_channels.h"

#include <string.h>

/*
 * Drive every family through the same state transitions. Runtime protocol
 * suites populate the counters from wire traffic; this focused test proves
 * that generic timeout/cancel/reset operations preserve and isolate them.
 */
int test_server_extension_lifecycle_focused(void)
{
    librdp_server_peer peer;

    memset(&peer, 0, sizeof(peer));
    peer.state = LIBRDP_SERVER_PEER_ACTIVE;
    rdp_server_extension_states_reset(&peer, 0);

    for (uint32_t value = (uint32_t)LIBRDP_SERVER_EXTENSION_UNKNOWN + 1u;
         value <= (uint32_t)LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING;
         value++)
    {
        librdp_server_extension_family family =
            (librdp_server_extension_family)value;
        librdp_server_extension_state snapshot;
        librdp_server_extension_state* state =
            rdp_server_extension_state_mut(&peer, family);
        uint16_t static_channel_id =
            (value & 1u) != 0u ? (uint16_t)(1000u + value) : 0u;
        uint32_t dynamic_channel_id =
            (value & 1u) == 0u ? 2000u + value : 0u;

        SCHECK(state != NULL && state->family == family &&
               state->reconnect_generation == 0u);
        rdp_server_extension_state_mark_open(&peer,
                                             family,
                                             static_channel_id,
                                             dynamic_channel_id,
                                             (uint8_t)(value & 3u));
        state->rx_messages = value;
        state->tx_messages = value + 1u;
        state->rx_bytes = (uint64_t)value * 11u;
        state->tx_bytes = (uint64_t)value * 13u;
        state->pending_requests = 2u;
        SCHECK(librdp_server_peer_record_extension_timeout(&peer, family) ==
               LIBRDP_STATUS_OK);
        SCHECK(state->pending_requests ==
                   (family == LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION
                        ? 0u
                        : 2u) &&
               state->timeout_count == 1u &&
               state->last_status == LIBRDP_STATUS_TIMEOUT);
        SCHECK(librdp_server_peer_cancel_extension(&peer, family) ==
               LIBRDP_STATUS_OK);
        SCHECK(librdp_server_extension_state_init(&snapshot) ==
               LIBRDP_STATUS_OK);
        SCHECK(librdp_server_peer_get_extension_state(&peer,
                                                      family,
                                                      &snapshot) ==
               LIBRDP_STATUS_OK);
        SCHECK(snapshot.family == family && snapshot.open && snapshot.active &&
               snapshot.cancelled && snapshot.pending_requests == 0u &&
               snapshot.open_count == 1u && snapshot.timeout_count == 1u &&
               snapshot.last_status == LIBRDP_STATUS_OK &&
               snapshot.rx_messages == value &&
               snapshot.tx_messages == value + 1u &&
               snapshot.rx_bytes == (uint64_t)value * 11u &&
               snapshot.tx_bytes == (uint64_t)value * 13u);
    }

    rdp_server_extension_states_reset(&peer, 1);
    for (uint32_t value = (uint32_t)LIBRDP_SERVER_EXTENSION_UNKNOWN + 1u;
         value <= (uint32_t)LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING;
         value++)
    {
        librdp_server_extension_state snapshot;
        librdp_server_extension_family family =
            (librdp_server_extension_family)value;

        SCHECK(librdp_server_extension_state_init(&snapshot) ==
               LIBRDP_STATUS_OK);
        SCHECK(librdp_server_peer_get_extension_state(&peer,
                                                      family,
                                                      &snapshot) ==
               LIBRDP_STATUS_OK);
        SCHECK(snapshot.family == family &&
               snapshot.reconnect_generation == 1u &&
               snapshot.close_count == 1u && !snapshot.open &&
               !snapshot.active && !snapshot.cancelled &&
               snapshot.pending_requests == 0u &&
               snapshot.open_count == 0u && snapshot.timeout_count == 0u &&
               snapshot.rx_messages == 0u && snapshot.tx_messages == 0u &&
               snapshot.rx_bytes == 0u && snapshot.tx_bytes == 0u &&
               snapshot.last_status == LIBRDP_STATUS_OK);
    }
    return 0;
}
