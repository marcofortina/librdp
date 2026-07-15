/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: workspace feed parsing example.
 * Invariants: local feed files are read into bounded memory and resources are
 * accessed only through public borrowed views.
 * Ownership: the workspace owns parsed resource strings until freed.
 * Threading: single-threaded file load and parse.
 * Trust boundary: workspace XML and embedded RDP file text are untrusted input.
 */

#include <librdp/librdp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char* path, char** data, size_t* length)
{
    FILE* file = NULL;
    long size = 0;
    char* buffer = NULL;

    if (!path || !data || !length)
        return 0;
    *data = NULL;
    *length = 0;
    file = fopen(path, "rb");
    if (!file)
        return 0;
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return 0;
    }
    size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return 0;
    }
    buffer = (char*)malloc((size_t)size);
    if (!buffer)
    {
        fclose(file);
        return 0;
    }
    if (fread(buffer, 1u, (size_t)size, file) != (size_t)size)
    {
        free(buffer);
        fclose(file);
        return 0;
    }
    fclose(file);
    *data = buffer;
    *length = (size_t)size;
    return 1;
}

static int is_url(const char* value)
{
    return value && (strncmp(value, "https://", 8u) == 0 || strncmp(value, "http://", 7u) == 0);
}

static const char* resource_type_name(librdp_workspace_resource_type type)
{
    switch (type)
    {
        case LIBRDP_WORKSPACE_RESOURCE_DESKTOP:
            return "desktop";
        case LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP:
            return "remote-app";
        default:
            return "unknown";
    }
}

static void print_resources(const librdp_workspace* workspace)
{
    size_t i = 0;
    size_t count = librdp_workspace_resource_count(workspace);

    for (i = 0; i < count; i++)
    {
        librdp_workspace_resource resource;

        if (librdp_workspace_resource_init(&resource) != LIBRDP_STATUS_OK ||
            librdp_workspace_resource_at(workspace, i, &resource) != LIBRDP_STATUS_OK)
            continue;
        printf("%zu type=%s title=\"%s\" alias=\"%s\"\n",
               i,
               resource_type_name(resource.type),
               resource.title ? resource.title : "",
               resource.alias ? resource.alias : "");
    }
}

int main(int argc, char** argv)
{
    librdp_workspace_config config;
    librdp_workspace* workspace = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    char* xml = NULL;
    size_t xml_len = 0;

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <feed-url-or-xml-file>\n", argv[0]);
        return 2;
    }
    if (librdp_workspace_config_init(&config) != LIBRDP_STATUS_OK)
        return 1;
    config.feed_url = is_url(argv[1]) ? argv[1] : NULL;
    workspace = librdp_workspace_new(&config);
    if (!workspace)
        return 1;
    if (config.feed_url)
        status = librdp_workspace_fetch(workspace);
    else if (read_file(argv[1], &xml, &xml_len))
        status = librdp_workspace_load_xml(workspace, xml, xml_len);
    else
        status = LIBRDP_STATUS_IO_ERROR;
    free(xml);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "workspace load failed: %s\n", librdp_status_name(status));
        librdp_workspace_free(workspace);
        return status == LIBRDP_STATUS_UNSUPPORTED ? 77 : 1;
    }
    print_resources(workspace);
    librdp_workspace_free(workspace);
    return 0;
}
