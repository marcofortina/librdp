/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_H
#define LIBRDP_H

/**
 * @defgroup librdp_umbrella Umbrella Header
 * @brief Convenience include for all public librdp API families.
 *
 * This header includes every public API header shipped by the library. It does
 * not create additional symbols or alter feature availability: optional
 * protocol paths and host backends must still be queried through the settings
 * and session feature-status APIs. ABI stability is provided by the exported
 * librdp_* symbol set and by version/size fields on evolvable public
 * structures. Including this header requires only the public C library
 * dependencies exposed by the individual headers.
 * @{
 */

#include <librdp/audio.h>
#include <librdp/channel.h>
#include <librdp/client.h>
#include <librdp/clipboard.h>
#include <librdp/error.h>
#include <librdp/event.h>
#include <librdp/input.h>
#include <librdp/session.h>
#include <librdp/settings.h>
#include <librdp/surface.h>
#include <librdp/video.h>

/** @} */

#endif
