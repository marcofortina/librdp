/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SETTINGS_H
#define LIBRDP_SETTINGS_H

#include <stddef.h>
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
#define LIBRDP_SETTINGS_MAX_STATIC_CHANNELS 16u /**< Maximum configured application static channels. */

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

#define LIBRDP_TLS_POLICY_VERSION 1u           /**< Current librdp_tls_policy version. */
#define LIBRDP_TLS_CERTIFICATE_INFO_VERSION 1u /**< Current librdp_tls_certificate_info version. */
#define LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH 64u /**< SHA-256 fingerprint length in lowercase hex. */
#define LIBRDP_CREDENTIALS_VERSION 1u          /**< Current librdp_credentials version. */
#define LIBRDP_DRIVE_POLICY_VERSION 1u         /**< Current librdp_drive_policy version. */
#define LIBRDP_USB_POLICY_VERSION 1u           /**< Current librdp_usb_policy version. */
#define LIBRDP_LIMITS_VERSION 1u               /**< Current librdp_limits version. */

/**
 * @brief TLS certificate trust policy used by TLS and NLA security modes.
 *
 * The default policy is LIBRDP_TLS_POLICY_STRICT with the system trust store
 * enabled. Less strict modes require explicit application configuration.
 *
 * @since 0.1.0
 */
typedef enum librdp_tls_policy_mode
{
    LIBRDP_TLS_POLICY_STRICT = 0,             /**< Require chain and hostname verification. */
    LIBRDP_TLS_POLICY_PINNED_FINGERPRINT = 1, /**< Accept only a configured leaf SHA-256 fingerprint. */
    LIBRDP_TLS_POLICY_TOFU = 2,               /**< Delegate trust-on-first-use decisions to the callback. */
    LIBRDP_TLS_POLICY_INSECURE_LAB = 3        /**< Disable TLS verification for explicit lab use only. */
} librdp_tls_policy_mode;

/**
 * @brief Certificate callback decision.
 *
 * The default decision keeps the configured policy result. ACCEPT is honored
 * only by policies that explicitly delegate trust to the callback, such as
 * TOFU. REJECT always rejects the certificate.
 *
 * @since 0.1.0
 */
typedef enum librdp_tls_certificate_decision
{
    LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT = 0, /**< Keep the policy's default result. */
    LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT = 1,  /**< Accept when the active policy allows callback trust. */
    LIBRDP_TLS_CERTIFICATE_DECISION_REJECT = 2   /**< Reject the certificate. */
} librdp_tls_certificate_decision;

/**
 * @brief TLS peer certificate information passed to policy callbacks.
 *
 * All pointer fields are borrowed and valid only for the duration of the
 * callback. der points to the leaf certificate DER bytes; host points to the
 * target host string from settings; subject and issuer are diagnostic strings
 * owned by the core. The fingerprint is always lowercase hexadecimal without
 * separators and is NUL-terminated.
 *
 * @since 0.1.0
 */
typedef struct librdp_tls_certificate_info
{
    uint32_t version;        /**< Struct version, LIBRDP_TLS_CERTIFICATE_INFO_VERSION. */
    uint32_t size;           /**< Size of this struct in bytes. */
    const char* host;        /**< Target host being verified; borrowed and non-NULL. */
    const uint8_t* der;      /**< Leaf certificate DER bytes; borrowed and non-NULL. */
    size_t der_len;          /**< Length of der in bytes. */
    char sha256_fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u]; /**< Leaf SHA-256 hex. */
    const char* subject;     /**< Leaf certificate subject string, or NULL when unavailable. */
    const char* issuer;      /**< Leaf certificate issuer string, or NULL when unavailable. */
    librdp_status verify_status; /**< Strict verification result before policy overrides. */
    long native_verify_result;   /**< TLS backend verification result for diagnostics. */
} librdp_tls_certificate_info;

/**
 * @brief Certificate policy callback.
 *
 * The callback runs synchronously on the thread performing
 * librdp_session_connect(). It must not retain pointers from certificate
 * beyond the call. user_data is the pointer stored in librdp_tls_policy.
 *
 * @param[in] certificate Certificate information; never NULL during callback.
 * @param[in,out] user_data Opaque application pointer; may be NULL.
 *
 * @return Decision for the active policy.
 *
 * @note Thread-safety: the callback is invoked synchronously from the session
 * connection thread; applications must serialize any state reached through
 * user_data.
 * @warning The callback receives certificate bytes and fingerprint material;
 * avoid logging or persisting them except for deliberate pinning or TOFU state.
 * @since 0.1.0
 */
typedef librdp_tls_certificate_decision (*librdp_tls_certificate_callback)(
    const librdp_tls_certificate_info* certificate,
    void* user_data);

/**
 * @brief Versioned TLS policy descriptor.
 *
 * Applications should initialize this struct with librdp_tls_policy_init()
 * before overriding fields. pinned_sha256 is copied by
 * librdp_settings_set_tls_policy() and may contain either 64 hexadecimal
 * characters or colon-separated hexadecimal octets. The callback pointer and
 * user_data are stored as-is and must remain valid until all sessions cloned
 * from the settings are destroyed.
 *
 * @since 0.1.0
 */
typedef struct librdp_tls_policy
{
    uint32_t version;  /**< Struct version, LIBRDP_TLS_POLICY_VERSION. */
    uint32_t size;     /**< Size of this struct in bytes. */
    librdp_tls_policy_mode mode; /**< Certificate trust policy mode. */
    int use_system_store;        /**< Non-zero to load and use the operating-system trust store. */
    const char* pinned_sha256;   /**< Optional leaf SHA-256 fingerprint for pinned mode; copied on set. */
    librdp_tls_certificate_callback certificate_callback; /**< Optional certificate decision callback. */
    void* certificate_callback_user_data; /**< Opaque pointer passed to certificate_callback. */
} librdp_tls_policy;

/**
 * @brief Versioned client credentials object.
 *
 * The object owns string copies installed with librdp_credentials_set().
 * librdp_credentials_clear() zeroizes password storage before release and
 * resets all fields. Applications may allocate this object on the stack, but
 * must initialize it before use.
 *
 * @since 0.1.0
 */
typedef struct librdp_credentials
{
    uint32_t version; /**< Struct version, LIBRDP_CREDENTIALS_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    char* username;   /**< Owned user name string, or NULL. */
    char* password;   /**< Owned password string, or NULL; zeroized by clear. */
    char* domain;     /**< Owned domain string, or NULL. */
} librdp_credentials;

/**
 * @brief Credentials provider callback.
 *
 * The callback runs synchronously on the thread performing
 * librdp_session_connect(), immediately before authentication data is needed.
 * credentials is initialized and owned by the caller; the provider should fill
 * it with librdp_credentials_set(). The core clears it after the connection
 * attempt and does not persist provider-supplied credentials. When a provider
 * is installed, its returned object replaces stored settings credentials for
 * that connection attempt; empty fields remain empty.
 *
 * @param[in,out] credentials Credentials object to fill; never NULL.
 * @param[in,out] user_data Opaque application pointer; may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success, or a status code to abort connection.
 *
 * @note Thread-safety: invoked synchronously from the session connection
 * thread. Applications must serialize user_data access as needed.
 * @warning Providers handle plaintext credentials; do not log them.
 * @since 0.1.0
 */
typedef librdp_status (*librdp_credentials_provider)(librdp_credentials* credentials,
                                                    void* user_data);

/**
 * @brief Versioned policy for redirected filesystem drives.
 *
 * Policies are copied into settings and then cloned into sessions. The default
 * initialized policy is conservative: read-only, device files denied, symlink
 * escapes denied, dotfiles denied, a finite per-drive handle limit, and no
 * explicit byte-size limit unless max_file_size is set by the application.
 *
 * @since 0.1.0
 */
typedef struct librdp_drive_policy
{
    uint32_t version;          /**< Struct version, LIBRDP_DRIVE_POLICY_VERSION. */
    uint32_t size;             /**< Size of this struct in bytes. */
    int read_only;             /**< Non-zero denies remote create, write, delete, rename, link, and truncate. */
    int deny_device_files;     /**< Non-zero denies non-regular, non-directory host objects. */
    int deny_symlink_escape;   /**< Non-zero resolves paths with O_NOFOLLOW component checks. */
    int deny_dotfiles;         /**< Non-zero denies path segments beginning with '.'. */
    uint64_t max_file_size;    /**< Maximum file size accepted for writes/truncation, or zero for no explicit cap. */
    uint32_t max_open_handles; /**< Maximum concurrently open drive handles, or zero to use the default. */
} librdp_drive_policy;

/**
 * @brief Versioned policy for redirected USB devices.
 *
 * The default initialized policy is default-deny outside explicit selectors:
 * a device must be configured with librdp_settings_add_usb_device(), HID and
 * mass-storage classes are denied, and transfer waits are capped. Applications
 * must opt in deliberately before exposing sensitive USB classes.
 *
 * @since 0.1.0
 */
typedef struct librdp_usb_policy
{
    uint32_t version;             /**< Struct version, LIBRDP_USB_POLICY_VERSION. */
    uint32_t size;                /**< Size of this struct in bytes. */
    int require_explicit_consent; /**< Non-zero requires an explicit configured selector before opening. */
    int allow_hid;                /**< Non-zero allows HID class devices and interfaces. */
    int allow_mass_storage;       /**< Non-zero allows mass-storage class devices and interfaces. */
    uint32_t max_transfer_ms;     /**< Maximum backend transfer wait in milliseconds, or zero for the default cap. */
} librdp_usb_policy;

/**
 * @brief Versioned runtime limit policy copied from settings into sessions.
 *
 * Initialize with librdp_limits_init(). Values of zero are not valid in an
 * installed policy; use the initialized defaults and then lower individual
 * fields as needed. The limits are hard caps enforced before allocation,
 * buffering, or outbound request queuing on the corresponding public/runtime
 * paths. They can restrict but cannot expand compile-time storage arrays.
 *
 * @since 0.1.0
 */
typedef struct librdp_limits
{
    uint32_t version;                       /**< Struct version, LIBRDP_LIMITS_VERSION. */
    uint32_t size;                          /**< Size of this struct in bytes. */
    uint32_t pdu_buffer_bytes;              /**< Maximum single decoded PDU/fragment buffer size in bytes. */
    uint32_t channel_buffer_bytes;          /**< Maximum static virtual-channel reassembly buffer size in bytes. */
    uint32_t dynamic_channel_count;         /**< Maximum active dynamic virtual channels. */
    uint32_t dynamic_channel_message_bytes; /**< Maximum dynamic-channel message payload size in bytes. */
    uint32_t clipboard_formats;             /**< Maximum remembered remote clipboard formats. */
    uint32_t clipboard_files;               /**< Maximum local clipboard files advertised at once. */
    uint32_t clipboard_file_range_bytes;    /**< Maximum bytes requested per clipboard file range. */
    uint32_t file_handles;                  /**< Maximum concurrently tracked redirected file/device handles. */
    uint32_t file_io_bytes;                 /**< Maximum file read/write IO payload size. */
    uint32_t device_io_bytes;               /**< Maximum device/PNP IO payload size. */
    uint32_t surface_count;                 /**< Maximum graphics surfaces tracked by the session. */
    uint32_t surface_max_dimension;         /**< Maximum surface width or height in pixels. */
    uint32_t frame_bytes;                   /**< Maximum frame/fast-path fragment buffer size in bytes. */
    uint32_t pending_requests;              /**< Maximum pending asynchronous requests per bounded queue. */
} librdp_limits;

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
 * @brief Reason why an optional feature is not currently usable.
 *
 * The value LIBRDP_FEATURE_REASON_NONE means the queried feature is usable at
 * the level reported by the status object. Other values identify the first
 * gating stage that prevents the feature from being used.
 *
 * @since 0.1.0
 */
typedef enum librdp_feature_unavailable_reason
{
    LIBRDP_FEATURE_REASON_NONE = 0,                /**< No feature gate currently blocks use. */
    LIBRDP_FEATURE_REASON_NOT_REQUESTED = 1,       /**< The feature bit is not enabled in settings. */
    LIBRDP_FEATURE_REASON_NOT_BUILT = 2,           /**< Required protocol support was not compiled. */
    LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE = 3, /**< Required application or OS backend is missing. */
    LIBRDP_FEATURE_REASON_NOT_NEGOTIATED = 4,      /**< The active session has not negotiated the feature. */
    LIBRDP_FEATURE_REASON_NOT_ACTIVE = 5,          /**< The feature is negotiated but has no active runtime stream. */
    LIBRDP_FEATURE_REASON_PARSER_ONLY = 6          /**< The implementation can parse the protocol but has no runtime path. */
} librdp_feature_unavailable_reason;

/**
 * @brief Public readiness snapshot for one optional feature.
 *
 * All boolean fields use 0 for false and non-zero for true. Settings-level
 * queries fill requested, built, backend_ready, and reason; session-level
 * queries additionally fill negotiated and active from live session state.
 *
 * @since 0.1.0
 */
typedef struct librdp_feature_status
{
    librdp_feature feature;                         /**< Single feature represented by this status. */
    int requested;                                  /**< Non-zero when the feature is enabled in settings. */
    int built;                                      /**< Non-zero when protocol support was compiled into the library. */
    int backend_ready;                              /**< Non-zero when required viewer or OS backend configuration exists. */
    int negotiated;                                 /**< Non-zero when a session negotiated the needed channel or capability. */
    int active;                                     /**< Non-zero when the negotiated feature currently has an active runtime. */
    librdp_feature_unavailable_reason reason;       /**< First reason preventing active use, or NONE when usable. */
} librdp_feature_status;

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
 * @brief Initialize a credentials object.
 *
 * Existing contents are overwritten without being freed, so call
 * librdp_credentials_clear() first when reusing a populated object.
 *
 * @param[out] credentials Credentials object to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * credentials is NULL.
 *
 * @note Thread-safety: this function only writes caller-owned memory.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_credentials_init(librdp_credentials* credentials);

/**
 * @brief Clear and release a credentials object.
 *
 * Passing NULL is allowed and has no effect. The password buffer, when present,
 * is zeroized before release. Other strings are freed normally.
 *
 * @param[in,out] credentials Credentials object to clear, or NULL.
 *
 * @note Thread-safety: the caller must serialize access to credentials.
 * @warning All pointers previously stored in credentials become invalid.
 * @since 0.1.0
 */
LIBRDP_API void librdp_credentials_clear(librdp_credentials* credentials);

/**
 * @brief Replace credentials with copied string values.
 *
 * The function copies each non-NULL input string. Passing NULL for a field
 * clears that field. On failure the credentials object is left unchanged.
 *
 * @param[in,out] credentials Initialized credentials object; must not be NULL.
 * @param[in] username User name string to copy, or NULL.
 * @param[in] password Password string to copy, or NULL.
 * @param[in] domain Domain string to copy, or NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * credentials, invalid version, or invalid size; LIBRDP_STATUS_NO_MEMORY when
 * a string copy fails.
 *
 * @note Thread-safety: the caller must serialize access to credentials.
 * @warning Password contents are retained until replaced or cleared.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_credentials_set(librdp_credentials* credentials,
                                                const char* username,
                                                const char* password,
                                                const char* domain);

/**
 * @brief Initialize runtime limits with conservative defaults.
 *
 * Defaults match the current bounded implementation: dynamic channel messages
 * are capped at 64 MiB, fast-path/frame fragments at 16 MiB, clipboard file
 * ranges and file IO at 4 MiB, and counts match the compiled session arrays.
 *
 * @param[out] limits Caller-owned limits object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * limits is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned memory.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_limits_init(librdp_limits* limits);

/**
 * @brief Set runtime limits for sessions created from settings.
 *
 * The limits descriptor is copied into settings. The descriptor must have
 * version LIBRDP_LIMITS_VERSION, a size large enough for librdp_limits, and
 * non-zero fields no larger than the implementation maxima. Passing NULL
 * restores defaults.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] limits Limits to copy, or NULL to restore defaults.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings, invalid metadata, zero fields, or values above implementation
 * maxima.
 *
 * @note Thread-safety: configure before constructing sessions, or serialize
 * externally with all settings readers.
 * @warning Lowering limits can cause later session operations to fail with
 * LIBRDP_STATUS_LIMIT_EXCEEDED when remote or local data exceeds the cap.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_limits(librdp_settings* settings,
                                                    const librdp_limits* limits);

/**
 * @brief Copy the currently configured runtime limits.
 *
 * @param[in] settings Settings object to query; must not be NULL.
 * @param[out] limits Destination limits object; must not be NULL and is fully
 * overwritten on success.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees settings.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_get_limits(const librdp_settings* settings,
                                                    librdp_limits* limits);

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
 * @brief Replace stored settings credentials from a credentials object.
 *
 * Passing NULL clears username, password, and domain. Non-NULL credentials must
 * have version LIBRDP_CREDENTIALS_VERSION and a valid size; strings are copied
 * into settings. The current per-field setters are compatible wrappers around
 * the same storage.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] credentials Credentials to copy, or NULL to clear stored credentials.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings or invalid credentials metadata; LIBRDP_STATUS_NO_MEMORY when a
 * string copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Stored passwords remain in settings memory until replaced or freed,
 * and are zeroized during replacement and cleanup.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_credentials(librdp_settings* settings,
                                                         const librdp_credentials* credentials);

/**
 * @brief Install or clear a just-in-time credentials provider.
 *
 * The callback pointer and user_data are stored by value. The provider is
 * called synchronously during librdp_session_connect() and provider-supplied
 * credentials are cleared immediately after the connection attempt. Passing
 * NULL clears the provider.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] provider Provider callback, or NULL to clear it.
 * @param[in,out] user_data Opaque pointer passed to provider; may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * settings is NULL.
 *
 * @note Thread-safety: configure before constructing or driving sessions, or
 * serialize externally.
 * @warning Provider callbacks receive and produce plaintext credentials; avoid
 * logging and retain them only as long as necessary.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_credentials_provider(librdp_settings* settings,
                                                                  librdp_credentials_provider provider,
                                                                  void* user_data);

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
 * @brief Initialize a TLS policy descriptor with strict defaults.
 *
 * The initialized policy uses LIBRDP_TLS_POLICY_STRICT, enables the system
 * trust store, clears pinning, and clears the certificate callback. The caller
 * owns the descriptor and may pass it to librdp_settings_set_tls_policy().
 *
 * @param[out] policy Policy descriptor to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * policy is NULL.
 *
 * @note Thread-safety: the function touches only caller-owned memory.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_tls_policy_init(librdp_tls_policy* policy);

/**
 * @brief Set the TLS certificate policy used by TLS and NLA connections.
 *
 * The policy descriptor must have version LIBRDP_TLS_POLICY_VERSION and a size
 * large enough for librdp_tls_policy. String fields are copied; callback and
 * user_data are stored by value. Passing a NULL policy resets strict defaults.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] policy Policy descriptor to copy, or NULL to restore defaults.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings, invalid versions, invalid modes, missing pin data for pinned mode,
 * missing callback for TOFU mode, or malformed fingerprints;
 * LIBRDP_STATUS_NO_MEMORY when the fingerprint copy fails.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning LIBRDP_TLS_POLICY_INSECURE_LAB disables certificate verification and
 * is intended only for controlled lab testing.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_tls_policy(librdp_settings* settings,
                                             const librdp_tls_policy* policy);

/**
 * @brief Copy the currently configured TLS policy into a caller descriptor.
 *
 * The returned pinned_sha256 pointer is borrowed from settings and remains
 * valid until the settings object is mutated or freed. Callback and user_data
 * are returned exactly as configured.
 *
 * @param[in] settings Settings object to query; must not be NULL.
 * @param[out] policy Destination descriptor; must not be NULL and is fully
 * overwritten on success.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_get_tls_policy(const librdp_settings* settings,
                                             librdp_tls_policy* policy);

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
 * @brief Initialize a redirected-drive policy with secure defaults.
 *
 * The initialized policy is read-only, denies device files, denies symlink
 * escapes, denies dotfiles, uses the default handle limit, and does not impose
 * an explicit file-size cap.
 *
 * @param[out] policy Policy object to initialize; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * policy is NULL.
 *
 * @note Thread-safety: this function only writes caller-owned memory.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_drive_policy_init(librdp_drive_policy* policy);

/**
 * @brief Set the policy for an existing redirected drive.
 *
 * The policy descriptor is validated and copied into settings. The index must
 * identify a drive previously added with librdp_settings_add_drive().
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] index Zero-based drive index.
 * @param[in] policy Policy to copy; must not be NULL and must have a valid
 * version and size.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings, NULL policy, invalid metadata, invalid index, or unsupported
 * values.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @warning Disabling read_only allows the remote server to modify files inside
 * the redirected root subject to the remaining policy checks.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_drive_policy(librdp_settings* settings,
                                                          uint32_t index,
                                                          const librdp_drive_policy* policy);

/**
 * @brief Copy the policy configured for an existing redirected drive.
 *
 * @param[in] settings Settings object to read; must not be NULL.
 * @param[in] index Zero-based drive index.
 * @param[out] policy Policy object to receive the copy; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments or invalid index.
 *
 * @note Thread-safety: settings are not internally synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_get_drive_policy(const librdp_settings* settings,
                                                          uint32_t index,
                                                          librdp_drive_policy* policy);

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
 * features are advertised or used later by a session. feature may be a bitmask
 * containing one or more known librdp_feature values. Unknown bits are
 * rejected so parser-only or unavailable protocols cannot be made visible as
 * enabled by mistake. Enabling a feature requests it; backend availability is
 * reported separately by librdp_settings_get_feature_status().
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] feature Feature bitmask to change; must contain only known
 * librdp_feature bits and must be non-zero.
 * @param[in] enabled Non-zero to enable the feature, zero to disable it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * settings, a zero feature value, or any unknown feature bit.
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
 * This is a raw settings bitmask query. It does not report build support,
 * backend readiness, server negotiation, or runtime active state; use
 * librdp_settings_get_feature_status() or librdp_session_get_feature_status()
 * for those readiness checks.
 *
 * @param[in] settings Settings object to query, or NULL.
 * @param[in] feature Feature bitmask to test; zero or any unknown bit is
 * treated as disabled.
 *
 * @return Non-zero when the feature is enabled; 0 when settings is NULL,
 * feature is zero, feature contains unknown bits, or the feature is disabled.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @since 0.1.0
 */
LIBRDP_API int librdp_settings_feature_enabled(const librdp_settings* settings, librdp_feature feature);

/**
 * @brief Query local readiness for one optional feature.
 *
 * The function validates one known feature bit and reports whether settings
 * request it, whether librdp was built with the relevant protocol path, and
 * whether the application supplied the required backend configuration. It does
 * not inspect a live server negotiation; use librdp_session_get_feature_status()
 * after creating a session for negotiated and active state.
 *
 * @param[in] settings Settings object to query; must not be NULL.
 * @param[in] feature Single known librdp_feature value to query; bitmasks with
 * multiple bits, zero, and unknown bits are rejected.
 * @param[out] status Destination status object; must not be NULL. The object is
 * written completely on success and contains no borrowed pointers.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers, zero features, multiple feature bits, or unknown feature bits.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the settings object.
 * @warning A feature can be requested and backend-ready while still unavailable
 * in a session if the server does not negotiate it.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_get_feature_status(const librdp_settings* settings,
                                                 librdp_feature feature,
                                                 librdp_feature_status* status);

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
 * @brief Initialize a USB redirection policy with conservative defaults.
 *
 * @param[out] policy Policy object to initialize; must not be NULL.
 *
 * @note Defaults require explicit selectors, deny HID and mass-storage
 * classes, and cap backend transfers to an implementation default.
 * @note Thread-safety: this function only writes caller-owned memory.
 * @since 0.1.0
 */
LIBRDP_API void librdp_usb_policy_init(librdp_usb_policy* policy);

/**
 * @brief Set the USB redirection policy.
 *
 * The policy is copied into settings. Passing NULL is invalid. The policy must
 * have a supported version and size.
 *
 * @param[in,out] settings Settings object to update; must not be NULL.
 * @param[in] policy Policy to copy; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, unsupported struct version or invalid size.
 *
 * @note Thread-safety: settings objects are not internally synchronized; the
 * caller must serialize concurrent reads and writes.
 * @warning Enabling HID or mass-storage redirection can expose keyboards,
 * pointing devices, removable media, and filesystems to the remote session.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_set_usb_policy(librdp_settings* settings,
                                                        const librdp_usb_policy* policy);

/**
 * @brief Return the active USB redirection policy.
 *
 * @param[in] settings Settings object to query; must not be NULL.
 * @param[out] policy Receives a copy of the policy; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments.
 *
 * @note Thread-safety: settings objects are not internally synchronized; the
 * caller must serialize concurrent reads and writes.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_settings_get_usb_policy(const librdp_settings* settings,
                                                        librdp_usb_policy* policy);

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
