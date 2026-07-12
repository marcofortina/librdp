/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SETTINGS_H
#define LIBRDP_SETTINGS_H

#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_settings Settings API
 * @brief Client connection, credential, feature, and device configuration functions.
 * @{
 */

#define LIBRDP_SETTINGS_MAX_DRIVES 8u         /**< Maximum configured redirected drives. */
#define LIBRDP_SETTINGS_MAX_PRINTERS 8u       /**< Maximum configured redirected printers. */
#define LIBRDP_SETTINGS_MAX_CAMERAS 8u        /**< Maximum configured redirected cameras. */
#define LIBRDP_SETTINGS_MAX_SMARTCARDS 8u     /**< Maximum configured redirected smartcards. */
#define LIBRDP_SETTINGS_MAX_USB_DEVICES 16u   /**< Maximum configured redirected USB devices. */
#define LIBRDP_SETTINGS_MAX_RAIL_APPS 16u     /**< Maximum configured remote applications. */
#define LIBRDP_SETTINGS_MAX_SERIAL_PORTS 8u   /**< Maximum configured redirected serial ports. */
#define LIBRDP_SETTINGS_MAX_PARALLEL_PORTS 8u /**< Maximum configured redirected parallel ports. */
#define LIBRDP_SETTINGS_MAX_PNP_DEVICES 32u   /**< Maximum configured redirected PNP devices. */

#define LIBRDP_PNP_DEVICE_CAP_LOCK_SUPPORTED 0x00000001u     /**< PNP device supports lock requests. */
#define LIBRDP_PNP_DEVICE_CAP_EJECT_SUPPORTED 0x00000002u    /**< PNP device supports eject requests. */
#define LIBRDP_PNP_DEVICE_CAP_REMOVABLE 0x00000004u          /**< PNP device is removable. */
#define LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK 0x00000008u /**< PNP device tolerates surprise removal. */

/**
 * @brief Opaque settings object used to configure new sessions.
 *
 * Settings own copies of strings and device descriptors configured through the
 * public setters. A session clones settings at construction time.
 *
 * @since 0.1.0
 */
typedef struct librdp_settings librdp_settings;

/**
 * @brief Security mode requested for the client connection.
 *
 * Values select the negotiation path used by librdp_session_connect().
 * Unsupported or policy-rejected values are reported by the settings setter.
 *
 * @since 0.1.0
 */
typedef enum librdp_security_mode
{
    LIBRDP_SECURITY_AUTO = 0,     /**< Let negotiation choose the strongest supported mode. */
    LIBRDP_SECURITY_STANDARD = 1, /**< Use legacy standard RDP security. */
    LIBRDP_SECURITY_TLS = 2,      /**< Use TLS transport security without network-level authentication. */
    LIBRDP_SECURITY_NLA = 3       /**< Use network-level authentication through CredSSP. */
} librdp_security_mode;

/**
 * @brief Optional feature bit advertised or enabled for a client session.
 *
 * Feature flags are stored in settings and copied into sessions. Enabling a
 * feature may require a corresponding backend in the viewer or application.
 *
 * @since 0.1.0
 */
typedef enum librdp_feature
{
    LIBRDP_FEATURE_AUDIO_OUTPUT = 0x00000001u,   /**< Enable audio playback redirection. */
    LIBRDP_FEATURE_AUDIO_INPUT = 0x00000002u,    /**< Enable microphone/audio capture redirection. */
    LIBRDP_FEATURE_VIDEO = 0x00000004u,          /**< Enable video optimized remoting. */
    LIBRDP_FEATURE_CAMERA = 0x00000008u,         /**< Enable camera/video capture redirection. */
    LIBRDP_FEATURE_SMARTCARD = 0x00000010u,      /**< Enable smartcard redirection. */
    LIBRDP_FEATURE_USB = 0x00000020u,            /**< Enable USB redirection. */
    LIBRDP_FEATURE_PNP = 0x00000040u,            /**< Enable plug-and-play device redirection. */
    LIBRDP_FEATURE_WEBAUTHN = 0x00000080u,       /**< Enable WebAuthn redirection. */
    LIBRDP_FEATURE_RAIL = 0x00000100u,           /**< Enable remote application integration. */
    LIBRDP_FEATURE_CR2 = 0x00000200u,            /**< Enable composited remoting. */
    LIBRDP_FEATURE_ECHO = 0x00000400u,           /**< Enable echo diagnostics channel. */
    LIBRDP_FEATURE_TELEMETRY = 0x00000800u,      /**< Enable telemetry channel. */
    LIBRDP_FEATURE_MULTITRANSPORT = 0x00001000u  /**< Enable multitransport negotiation. */
} librdp_feature;

/**
 * @brief Allocate a settings object with default client values.
 *
 * Defaults are port 3389, desktop size 1024x768, no credentials, no target,
 * no optional devices, and LIBRDP_SECURITY_AUTO.
 *
 * @return Newly allocated settings object owned by the caller, or NULL when
 * memory cannot be allocated.
 *
 * @note Thread-safety: settings objects are not internally synchronized.
 * Mutate or read a settings object from one serialized context at a time.
 * @since 0.1.0
 */
LIBRDP_API librdp_settings* librdp_settings_new(void);

/**
 * @brief Deep-copy a settings object.
 *
 * All configured strings, device entries, features, security mode, and desktop
 * values are copied. The returned object is independent from the source.
 *
 * @param[in] settings Settings to clone; must not be NULL.
 *
 * @return Newly allocated copy owned by the caller, or NULL when settings is
 * NULL, memory allocation fails, or any entry cannot be copied.
 *
 * @note Thread-safety: the source settings object must not be mutated while it
 * is being cloned.
 * @warning Password material, when configured, is copied into the clone.
 * @since 0.1.0
 */
LIBRDP_API librdp_settings* librdp_settings_clone(const librdp_settings* settings);

/**
 * @brief Free a settings object.
 *
 * Passing NULL is allowed and has no effect. All strings and device entries
 * owned by the object are released.
 *
 * @param[in,out] settings Settings object to free, or NULL.
 *
 * @note Thread-safety: the caller must ensure no other thread is reading or
 * mutating the settings object.
 * @warning Any pointers returned by settings getter functions become invalid.
 * @since 0.1.0
 */
LIBRDP_API void librdp_settings_free(librdp_settings* settings);

/**
 * @brief Set the remote target host name or address.
 *
 * The target string is copied during the call and must be non-empty.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] target NUL-terminated target string; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or empty arguments; LIBRDP_STATUS_NO_MEMORY when the string copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_target(librdp_settings* settings, const char* target);

/**
 * @brief Set or clear the user name used by client authentication.
 *
 * Non-NULL strings are copied during the call. Passing NULL clears the stored
 * user name.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] username NUL-terminated user name to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * settings is NULL; LIBRDP_STATUS_NO_MEMORY when the string copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_username(librdp_settings* settings, const char* username);

/**
 * @brief Set or clear the password used by client authentication.
 *
 * Non-NULL strings are copied during the call. Passing NULL clears the stored
 * password.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] password NUL-terminated password to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * settings is NULL; LIBRDP_STATUS_NO_MEMORY when the string copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning The password is retained in process memory until replaced or the
 * settings object is freed.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_password(librdp_settings* settings, const char* password);

/**
 * @brief Set or clear the authentication domain.
 *
 * Non-NULL strings are copied during the call. Passing NULL clears the stored
 * domain.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] domain NUL-terminated domain string to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * settings is NULL; LIBRDP_STATUS_NO_MEMORY when the string copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_domain(librdp_settings* settings, const char* domain);

/**
 * @brief Set the TCP port used for the RDP connection.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] port TCP port; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * settings is NULL or port is 0.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_port(librdp_settings* settings, uint16_t port);

/**
 * @brief Set the requested initial desktop size.
 *
 * Width and height must be non-zero and no larger than 8192 pixels.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] width Requested desktop width in pixels.
 * @param[in] height Requested desktop height in pixels.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or invalid dimensions.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_desktop_size(librdp_settings* settings, uint32_t width, uint32_t height);

/**
 * @brief Set the requested security mode.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] mode Security mode value in the librdp_security_mode enum.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or unsupported mode values.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Weaker security modes are exposed for interoperability and should
 * be selected only when the deployment requires them.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_security_mode(librdp_settings* settings, librdp_security_mode mode);

/**
 * @brief Add a redirected filesystem drive.
 *
 * The drive name and path are copied. The name must be non-empty, at most
 * seven bytes, and must not contain characters rejected by the implementation.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] name Advertised drive name; must not be NULL or empty.
 * @param[in] path Host filesystem path; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the drive limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the path copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Redirected drives expose host filesystem content to the remote
 * session according to later protocol requests and backend policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_drive(librdp_settings* settings, const char* name, const char* path);

/**
 * @brief Add a redirected serial port.
 *
 * The port name and host path are copied. The name follows the same validation
 * rules as drive names.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] name Advertised serial port name; must not be NULL or empty.
 * @param[in] path Host serial device path; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the serial-port limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the path copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Redirected serial devices can expose host hardware to the remote
 * session.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_serial_port(librdp_settings* settings,
                                              const char* name,
                                              const char* path);

/**
 * @brief Add a redirected parallel port.
 *
 * The port name and host path are copied. The name follows the same validation
 * rules as drive names.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] name Advertised parallel port name; must not be NULL or empty.
 * @param[in] path Host parallel device path; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the parallel-port limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the path copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Redirected parallel devices can expose host hardware to the remote
 * session.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_parallel_port(librdp_settings* settings,
                                                const char* name,
                                                const char* path);

/**
 * @brief Add a redirected printer.
 *
 * Printer name, driver name, and output path are copied. Printer and driver
 * names must be non-empty and at most 127 bytes; output_path must be non-empty.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] name Advertised printer name; must not be NULL or empty.
 * @param[in] driver Advertised driver name; must not be NULL or empty.
 * @param[in] output_path Host path or backend target for output; must not be
 * NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the printer limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when metadata cannot be copied.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Remote print jobs may write host files or reach host print
 * backends according to the configured output path.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_printer(librdp_settings* settings,
                                          const char* name,
                                          const char* driver,
                                          const char* output_path);
/**
 * @brief Enable or disable an optional client feature flag.
 *
 * Feature flags control whether optional protocol channels or viewer-backed
 * features are advertised or used later by a session.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] feature Feature bit to change; must be non-zero.
 * @param[in] enabled Non-zero to enable the feature, zero to disable it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or a zero feature value.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_enable_feature(librdp_settings* settings,
                                             librdp_feature feature,
                                             int enabled);

/**
 * @brief Test whether an optional client feature flag is enabled.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] feature Feature bit to test; zero is treated as disabled.
 *
 * @return Non-zero when the feature is enabled; 0 when settings is NULL,
 * feature is zero, or the feature is disabled.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API int librdp_settings_feature_enabled(const librdp_settings* settings, librdp_feature feature);

/**
 * @brief Set or clear the audio output device selector.
 *
 * Non-NULL selectors must be non-empty and within the implementation text
 * length limit. The selector is copied during the call; passing NULL clears it.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] device Device selector to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or invalid non-NULL selector; LIBRDP_STATUS_NO_MEMORY when the copy
 * fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_audio_output_device(librdp_settings* settings, const char* device);

/**
 * @brief Set or clear the audio input device selector.
 *
 * Non-NULL selectors must be non-empty and within the implementation text
 * length limit. The selector is copied during the call; passing NULL clears it.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] device Device selector to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or invalid non-NULL selector; LIBRDP_STATUS_NO_MEMORY when the copy
 * fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Audio input selectors can enable microphone capture once the
 * feature is used by a viewer backend.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_audio_input_device(librdp_settings* settings, const char* device);

/**
 * @brief Set or clear the video output path selector.
 *
 * Non-NULL paths must be non-empty and within the implementation text length
 * limit. The path is copied during the call; passing NULL clears it.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] path Output path to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or invalid non-NULL path; LIBRDP_STATUS_NO_MEMORY when the copy
 * fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_video_output_path(librdp_settings* settings, const char* path);

/**
 * @brief Add a camera source selector.
 *
 * The source string is copied and must be non-empty and within the
 * implementation text length limit.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] source Camera source selector; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the camera limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Camera sources can expose host camera devices to the remote session
 * when the camera feature is enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_camera(librdp_settings* settings, const char* source);

/**
 * @brief Add a smartcard source selector.
 *
 * The source string is copied and must be non-empty and within the
 * implementation text length limit.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] source Smartcard source selector; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the smartcard limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Smartcard redirection can expose authentication devices and tokens
 * to the remote session according to backend policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_smartcard(librdp_settings* settings, const char* source);

/**
 * @brief Add a USB device selector.
 *
 * The selector string is copied and must be non-empty and within the
 * implementation text length limit.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] selector USB selector; must not be NULL or empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the USB device limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning USB redirection can expose host devices to the remote session.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_usb_device(librdp_settings* settings, const char* selector);

/**
 * @brief Add a Plug and Play device advertisement.
 *
 * Hardware ID, compatibility ID, and description are copied and must be
 * non-empty and within the implementation text length limit. device_caps may
 * contain only LIBRDP_PNP_DEVICE_CAP_* bits.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] hardware_id Hardware identifier; must not be NULL or empty.
 * @param[in] compatibility_id Compatibility identifier; must not be NULL or
 * empty.
 * @param[in] description Human-readable description; must not be NULL or empty.
 * @param[in] device_caps Device capability bitmask.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments, unsupported capability bits, or when the PNP device
 * limit is reached; LIBRDP_STATUS_NO_MEMORY when metadata cannot be copied.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning PNP device advertisements affect what host devices the remote
 * session may discover and request.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_pnp_device(librdp_settings* settings,
                                             const char* hardware_id,
                                             const char* compatibility_id,
                                             const char* description,
                                             uint32_t device_caps);

/**
 * @brief Set or clear the WebAuthn provider selector.
 *
 * Accepted non-NULL provider values are "mock", "fido2", "mock=<path>", and
 * "fido2=<path>". Passing NULL clears the provider.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] provider Provider selector to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or unsupported provider text; LIBRDP_STATUS_NO_MEMORY when the copy
 * fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning WebAuthn providers can expose authentication operations to the
 * remote session according to backend policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_webauthn_provider(librdp_settings* settings, const char* provider);

/**
 * @brief Add a remote application launch request.
 *
 * The application string is copied and must be non-empty and within the
 * implementation text length limit.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] app Remote application command or identifier; must not be NULL or
 * empty.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments or when the RAIL app limit is reached;
 * LIBRDP_STATUS_NO_MEMORY when the copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning The remote session may execute the configured application after
 * connection when RAIL is enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_add_rail_app(librdp_settings* settings, const char* app);

/**
 * @brief Set or clear the echo channel payload.
 *
 * Non-NULL payloads must be non-empty and within the implementation text length
 * limit. The payload is copied during the call; passing NULL clears it.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] payload Payload to copy, or NULL to clear.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or invalid non-NULL payload; LIBRDP_STATUS_NO_MEMORY when the copy
 * fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_echo_payload(librdp_settings* settings, const char* payload);
/**
 * @brief Return the number of configured redirected drives.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Drive count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_drive_count(const librdp_settings* settings);

/**
 * @brief Return the advertised name of a configured redirected drive.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Drive index in the range returned by
 * librdp_settings_drive_count().
 *
 * @return Internal NUL-terminated drive name, or NULL when settings is NULL or
 * index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_drive_name(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the host path of a configured redirected drive.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Drive index in the range returned by
 * librdp_settings_drive_count().
 *
 * @return Internal NUL-terminated path, or NULL when settings is NULL or index
 * is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_drive_path(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the number of configured redirected serial ports.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Serial port count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_serial_port_count(const librdp_settings* settings);

/**
 * @brief Return the advertised name of a configured serial port.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Serial port index in the range returned by
 * librdp_settings_serial_port_count().
 *
 * @return Internal NUL-terminated name, or NULL when settings is NULL or index
 * is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_serial_port_name(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the host path of a configured serial port.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Serial port index in the range returned by
 * librdp_settings_serial_port_count().
 *
 * @return Internal NUL-terminated path, or NULL when settings is NULL or index
 * is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_serial_port_path(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the number of configured redirected parallel ports.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Parallel port count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_parallel_port_count(const librdp_settings* settings);

/**
 * @brief Return the advertised name of a configured parallel port.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Parallel port index in the range returned by
 * librdp_settings_parallel_port_count().
 *
 * @return Internal NUL-terminated name, or NULL when settings is NULL or index
 * is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_parallel_port_name(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the host path of a configured parallel port.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Parallel port index in the range returned by
 * librdp_settings_parallel_port_count().
 *
 * @return Internal NUL-terminated path, or NULL when settings is NULL or index
 * is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_parallel_port_path(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the number of configured redirected printers.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Printer count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_printer_count(const librdp_settings* settings);

/**
 * @brief Return the advertised name of a configured printer.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Printer index in the range returned by
 * librdp_settings_printer_count().
 *
 * @return Internal NUL-terminated name, or NULL when settings is NULL or index
 * is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_printer_name(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the driver name of a configured printer.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Printer index in the range returned by
 * librdp_settings_printer_count().
 *
 * @return Internal NUL-terminated driver name, or NULL when settings is NULL or
 * index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_printer_driver(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the output path of a configured printer.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Printer index in the range returned by
 * librdp_settings_printer_count().
 *
 * @return Internal NUL-terminated output path, or NULL when settings is NULL
 * or index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_printer_output_path(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the configured audio output device selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated selector, or NULL when unset or settings is
 * NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_audio_output_device(const librdp_settings* settings);

/**
 * @brief Return the configured audio input device selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated selector, or NULL when unset or settings is
 * NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_audio_input_device(const librdp_settings* settings);

/**
 * @brief Return the configured video output path selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated path, or NULL when unset or settings is NULL.
 * The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_video_output_path(const librdp_settings* settings);

/**
 * @brief Return the number of configured camera sources.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Camera source count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_camera_count(const librdp_settings* settings);

/**
 * @brief Return a configured camera source selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Camera source index in the range returned by
 * librdp_settings_camera_count().
 *
 * @return Internal NUL-terminated selector, or NULL when settings is NULL or
 * index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_camera_source(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the number of configured smartcard sources.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Smartcard source count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_smartcard_count(const librdp_settings* settings);

/**
 * @brief Return a configured smartcard source selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Smartcard source index in the range returned by
 * librdp_settings_smartcard_count().
 *
 * @return Internal NUL-terminated selector, or NULL when settings is NULL or
 * index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_smartcard_source(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the number of configured USB device selectors.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return USB selector count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_usb_device_count(const librdp_settings* settings);

/**
 * @brief Return a configured USB device selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index USB selector index in the range returned by
 * librdp_settings_usb_device_count().
 *
 * @return Internal NUL-terminated selector, or NULL when settings is NULL or
 * index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_usb_device_selector(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the number of configured PNP device advertisements.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return PNP device count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_pnp_device_count(const librdp_settings* settings);

/**
 * @brief Return a configured PNP hardware identifier.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index PNP device index in the range returned by
 * librdp_settings_pnp_device_count().
 *
 * @return Internal NUL-terminated hardware ID, or NULL when settings is NULL
 * or index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_pnp_device_hardware_id(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return a configured PNP compatibility identifier.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index PNP device index in the range returned by
 * librdp_settings_pnp_device_count().
 *
 * @return Internal NUL-terminated compatibility ID, or NULL when settings is
 * NULL or index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_pnp_device_compatibility_id(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return a configured PNP device description.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index PNP device index in the range returned by
 * librdp_settings_pnp_device_count().
 *
 * @return Internal NUL-terminated description, or NULL when settings is NULL
 * or index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_pnp_device_description(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return configured PNP device capability bits.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index PNP device index in the range returned by
 * librdp_settings_pnp_device_count().
 *
 * @return Capability bitmask, or 0 when settings is NULL or index is out of
 * range.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_pnp_device_caps(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the configured WebAuthn provider selector.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated provider selector, or NULL when unset or
 * settings is NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_webauthn_provider(const librdp_settings* settings);

/**
 * @brief Return the number of configured remote application entries.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Remote application count, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_rail_app_count(const librdp_settings* settings);

/**
 * @brief Return a configured remote application entry.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] index Remote application index in the range returned by
 * librdp_settings_rail_app_count().
 *
 * @return Internal NUL-terminated application string, or NULL when settings is
 * NULL or index is out of range. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_rail_app(const librdp_settings* settings, uint32_t index);

/**
 * @brief Return the configured echo channel payload.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated payload, or NULL when unset or settings is
 * NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_echo_payload(const librdp_settings* settings);

/**
 * @brief Return the configured target host name or address.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated target string, or NULL when unset or settings
 * is NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_target(const librdp_settings* settings);

/**
 * @brief Return the configured user name.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated user name, or NULL when unset or settings is
 * NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_username(const librdp_settings* settings);

/**
 * @brief Return the configured authentication domain.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Internal NUL-terminated domain string, or NULL when unset or settings
 * is NULL. The caller must not free or modify the string.
 *
 * @note Thread-safety: the returned pointer remains valid until the settings
 * object is mutated or freed.
 * @since 0.1.0
 */
LIBRDP_API const char* librdp_settings_domain(const librdp_settings* settings);

/**
 * @brief Return the configured TCP port.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Configured port, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint16_t librdp_settings_port(const librdp_settings* settings);

/**
 * @brief Return the configured initial desktop width.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Width in pixels, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_width(const librdp_settings* settings);

/**
 * @brief Return the configured initial desktop height.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Height in pixels, or 0 when settings is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_settings_height(const librdp_settings* settings);

/**
 * @brief Return the configured security mode.
 *
 * @param[in] settings Settings object to query, or NULL.
 *
 * @return Configured security mode, or LIBRDP_SECURITY_AUTO when settings is
 * NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API librdp_security_mode librdp_settings_security_mode(const librdp_settings* settings);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
