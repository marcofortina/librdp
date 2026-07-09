#include "licensing/licensing.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_license_preamble preamble;
    rdp_license_binary_blob blob;
    rdp_license_product_info product;
    rdp_license_server_request request;
    rdp_license_platform_challenge challenge;
    rdp_license_new_or_upgrade license;
    rdp_license_new_license_info info;
    rdp_license_hardware_id hardware_id;
    rdp_license_platform_challenge_response_data challenge_data;
    rdp_license_error_alert alert;
    rdp_buffer buffer;
    rdp_license_binary_blob encrypted;
    uint8_t random[32] = {0};

    (void)rdp_license_parse_preamble(data, size, &preamble);
    (void)rdp_license_parse_binary_blob(data, size, &blob);
    (void)rdp_license_parse_product_info(data, size, &product);
    (void)rdp_license_parse_server_request(data, size, &request);
    (void)rdp_license_parse_platform_challenge(data, size, &challenge);
    (void)rdp_license_parse_new_or_upgrade(data, size, &license);
    (void)rdp_license_parse_new_license_info(data, size, &info);
    (void)rdp_license_parse_hardware_id(data, size, &hardware_id);
    (void)rdp_license_parse_platform_challenge_response_data(data, size, &challenge_data);
    (void)rdp_license_parse_error_alert(data, size, &alert);

    rdp_buffer_init(&buffer);
    (void)rdp_license_write_error_alert(&buffer,
                                        RDP_LICENSE_VERSION_3,
                                        1,
                                        2,
                                        RDP_LICENSE_BLOB_DATA,
                                        data,
                                        size > UINT16_MAX ? UINT16_MAX : (uint16_t)size);
    buffer.length = 0;
    encrypted.type = RDP_LICENSE_BLOB_ENCRYPTED_DATA;
    encrypted.length = size > 32u ? 32u : (uint16_t)size;
    encrypted.data = data;
    (void)rdp_license_write_platform_challenge_response(&buffer,
                                                        RDP_LICENSE_VERSION_3,
                                                        &encrypted,
                                                        &encrypted,
                                                        random);
    rdp_buffer_free(&buffer);
    return 0;
}
