/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: feature readiness, extension state, status, and metrics.
 * Invariants: built, provider-ready, negotiated, and active remain distinct.
 * Ownership: feature and metrics state is stored by listeners and peers.
 * Threading: status queries follow the owning object's serialization contract.
 * Trust boundary: negotiated state derives only from validated channel state.
 */

#ifndef RDP_SERVER_FEATURES_H
#define RDP_SERVER_FEATURES_H

#include "server/server_common.h"

void rdp_server_metric_add(uint64_t* metric, uint64_t value);

int rdp_server_valid_feature_mask(librdp_feature feature);

int rdp_server_valid_single_feature(librdp_feature feature);

int rdp_server_extension_family_valid(librdp_server_extension_family family);

uint64_t rdp_server_extension_family_bit(librdp_server_extension_family family);

int rdp_server_extension_provider_ready(uint64_t providers,
                                               librdp_server_extension_family family);

librdp_feature rdp_server_feature_for_extension_family(librdp_server_extension_family family);

int rdp_server_feature_extension_provider_ready(uint64_t providers, librdp_feature feature);

int rdp_server_feature_provider_mask_valid(librdp_feature feature);

int rdp_server_listener_feature_backend_ready(const librdp_server* server, librdp_feature feature);

void rdp_server_fill_feature_status(uint32_t requested_features,
                                           librdp_feature feature,
                                           int backend_ready,
                                           librdp_feature_status* status);

librdp_status librdp_server_status_init(librdp_server_status* status);

librdp_status librdp_server_metrics_init(librdp_server_metrics* metrics);

librdp_status librdp_server_extension_state_init(librdp_server_extension_state* state);

#endif
