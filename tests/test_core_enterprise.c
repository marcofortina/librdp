/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: workspace and administration tests.
 * Coverage: feed parsing, HTTP, WinRM, ownership, and errors.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

/*
 * Coverage: validates workspace object ownership and unsupported backend
 * status before XML/feed runtime backends are compiled into the library.
 */
int test_workspace_lifecycle(void)
{
    librdp_workspace_config config;
    librdp_workspace_resource resource;
    librdp_workspace* workspace = NULL;
    char domain[32];
    char password[32];
    char username[32];

    test_core_fill_secret(domain, sizeof(domain), 211u);
    test_core_fill_secret(password, sizeof(password), 223u);
    test_core_fill_secret(username, sizeof(username), 227u);
    CHECK(librdp_workspace_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_workspace_resource_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_workspace_config_init(&config) == LIBRDP_STATUS_OK);
    CHECK(config.version == LIBRDP_WORKSPACE_CONFIG_VERSION);
    CHECK(config.size == sizeof(config));
    CHECK(config.timeout_ms > 0);
    CHECK(librdp_workspace_new(NULL) == NULL);

    config.feed_url = "https://workspace.example.test/feed";
    config.username = username;
    config.password = password;
    config.domain = domain;
    workspace = librdp_workspace_new(&config);
    CHECK(workspace != NULL);
    CHECK(librdp_workspace_resource_count(workspace) == 0);
    CHECK(librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_at(workspace, 0, &resource) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_workspace_clear(workspace) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_count(workspace) == 0);
#if !defined(RDP_HAVE_CURL) || !defined(RDP_HAVE_LIBXML2)
    CHECK(librdp_workspace_fetch(workspace) == LIBRDP_STATUS_UNSUPPORTED);
#endif
#ifdef RDP_HAVE_LIBXML2
    CHECK(librdp_workspace_load_xml(workspace, "<workspace/>", 12u) == LIBRDP_STATUS_OK);
#else
    CHECK(librdp_workspace_load_xml(workspace, "<workspace/>", 12u) == LIBRDP_STATUS_UNSUPPORTED);
#endif
    librdp_workspace_free(workspace);

    CHECK(librdp_workspace_config_init(&config) == LIBRDP_STATUS_OK);
    workspace = librdp_workspace_new(&config);
    CHECK(workspace != NULL);
    CHECK(librdp_workspace_fetch(workspace) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_workspace_load_xml(workspace, NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_workspace_free(workspace);
    return 0;
}

/*
 * Coverage: parses a synthetic workspace feed through libxml2 and verifies
 * resource ownership, malformed XML handling, and oversized feed rejection.
 */
int test_workspace_xml_parse(void)
{
    static const char feed[] =
        "<?xml version=\"1.0\"?>"
        "<Workspace>"
        "  <Resources>"
        "    <Resource>"
        "      <ID>desktop-1</ID>"
        "      <Title>Desktop</Title>"
        "      <Type>Desktop</Type>"
        "      <RDPFileContents>full address:s:desktop.example.test</RDPFileContents>"
        "      <IconUrl>https://workspace.example.test/desktop.png</IconUrl>"
        "      <TerminalServer>desktop.example.test</TerminalServer>"
        "    </Resource>"
        "    <RemoteApp id=\"app-1\">"
        "      <Title>Accounting</Title>"
        "      <Alias>acct</Alias>"
        "      <RDPFileUrl>https://workspace.example.test/acct.rdp</RDPFileUrl>"
        "      <RemoteAppProgram>||acct</RemoteAppProgram>"
        "    </RemoteApp>"
        "  </Resources>"
        "</Workspace>";
    static const char malformed[] = "<Workspace><Resources><Resource>";
    const size_t oversize_len = (4u * 1024u * 1024u) + 1u;
    librdp_workspace_config config;
    librdp_workspace_resource resource;
    librdp_workspace* workspace = NULL;
    char* oversize = NULL;

    CHECK(librdp_workspace_config_init(&config) == LIBRDP_STATUS_OK);
    workspace = librdp_workspace_new(&config);
    CHECK(workspace != NULL);
    CHECK(librdp_workspace_load_xml(workspace, feed, sizeof(feed) - 1u) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_count(workspace) == 2u);

    CHECK(librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_at(workspace, 0, &resource) == LIBRDP_STATUS_OK);
    CHECK(resource.type == LIBRDP_WORKSPACE_RESOURCE_DESKTOP);
    CHECK(resource.id && strcmp(resource.id, "desktop-1") == 0);
    CHECK(resource.title && strcmp(resource.title, "Desktop") == 0);
    CHECK(resource.rdp_file_contents && strstr(resource.rdp_file_contents, "desktop.example.test") != NULL);
    CHECK(resource.terminal_server && strcmp(resource.terminal_server, "desktop.example.test") == 0);

    CHECK(librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_at(workspace, 1, &resource) == LIBRDP_STATUS_OK);
    CHECK(resource.type == LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP);
    CHECK(resource.id && strcmp(resource.id, "app-1") == 0);
    CHECK(resource.alias && strcmp(resource.alias, "acct") == 0);
    CHECK(resource.rdp_file_url && strstr(resource.rdp_file_url, "acct.rdp") != NULL);
    CHECK(resource.remote_app_program && strcmp(resource.remote_app_program, "||acct") == 0);

    CHECK(librdp_workspace_load_xml(workspace, malformed, sizeof(malformed) - 1u) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_workspace_resource_count(workspace) == 2u);

    oversize = (char*)malloc(oversize_len);
    CHECK(oversize != NULL);
    memset(oversize, ' ', oversize_len);
    CHECK(librdp_workspace_load_xml(workspace, oversize, oversize_len) == LIBRDP_STATUS_LIMIT_EXCEEDED);
    free(oversize);

    librdp_workspace_free(workspace);
    return 0;
}

static int test_workspace_http_listen(uint16_t* port)
{
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);
    int fd = -1;
    int one = 1;

    if (!port)
        return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0 ||
        listen(fd, 1) != 0)
    {
        close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

static int test_workspace_write_all(int fd, const char* data, size_t length)
{
    size_t written = 0;

    while (written < length)
    {
        ssize_t result = write(fd, data + written, length - written);

        if (result <= 0)
            return 0;
        written += (size_t)result;
    }
    return 1;
}

/*
 * Fixture: serves one workspace feed over loopback HTTP so fetch coverage does
 * not depend on external RDS infrastructure or credentials.
 */
static int test_workspace_http_child(int listen_fd)
{
    static const char feed[] =
        "<Workspace><Resources><Resource><Title>Remote Desktop</Title><Type>Desktop</Type>"
        "<RDPFileContents>full address:s:desktop.example.test</RDPFileContents>"
        "</Resource></Resources></Workspace>";
    char request[1024];
    char header[256];
    size_t used = 0;
    int client = -1;
    int header_len = 0;

    client = accept(listen_fd, NULL, NULL);
    if (client < 0)
        return 1;
    while (used + 1u < sizeof(request))
    {
        ssize_t got = read(client, request + used, sizeof(request) - used - 1u);

        if (got <= 0)
        {
            close(client);
            return 1;
        }
        used += (size_t)got;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n"))
            break;
    }
    if (!strstr(request, "GET /feed HTTP/"))
    {
        close(client);
        return 1;
    }
    header_len = snprintf(header,
                          sizeof(header),
                          "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                          sizeof(feed) - 1u);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header) ||
        !test_workspace_write_all(client, header, (size_t)header_len) ||
        !test_workspace_write_all(client, feed, sizeof(feed) - 1u))
    {
        close(client);
        return 1;
    }
    close(client);
    return 0;
}

int test_workspace_fetch_http(void)
{
    librdp_workspace_config config;
    librdp_workspace_resource resource;
    librdp_workspace* workspace = NULL;
    char url[128];
    uint16_t port = 0;
    int listen_fd = -1;
    pid_t child = -1;
    int child_status = 0;

    listen_fd = test_workspace_http_listen(&port);
    CHECK(listen_fd >= 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0)
    {
        int rc = test_workspace_http_child(listen_fd);

        close(listen_fd);
        _exit(rc);
    }
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/feed", (unsigned)port);
    CHECK(librdp_workspace_config_init(&config) == LIBRDP_STATUS_OK);
    config.feed_url = url;
    config.timeout_ms = 5000u;
    workspace = librdp_workspace_new(&config);
    CHECK(workspace != NULL);
    CHECK(librdp_workspace_fetch(workspace) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_count(workspace) == 1u);
    CHECK(librdp_workspace_resource_init(&resource) == LIBRDP_STATUS_OK);
    CHECK(librdp_workspace_resource_at(workspace, 0, &resource) == LIBRDP_STATUS_OK);
    CHECK(resource.type == LIBRDP_WORKSPACE_RESOURCE_DESKTOP);
    CHECK(resource.title && strcmp(resource.title, "Remote Desktop") == 0);
    CHECK(resource.rdp_file_contents && strstr(resource.rdp_file_contents, "desktop.example.test") != NULL);
    librdp_workspace_free(workspace);
    close(listen_fd);
    CHECK(waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates admin inventory object ownership, versioned public views,
 * and the query status contract when transport backends are not compiled.
 */
int test_admin_lifecycle(void)
{
    librdp_admin_config config;
    librdp_admin_session session;
    librdp_admin_action action;
    librdp_admin* admin = NULL;
    char domain[32];
    char password[32];
    char username[32];

    test_core_fill_secret(domain, sizeof(domain), 229u);
    test_core_fill_secret(password, sizeof(password), 233u);
    test_core_fill_secret(username, sizeof(username), 239u);
    CHECK(librdp_admin_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_admin_session_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_admin_action_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_admin_config_init(&config) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_action_init(&action) == LIBRDP_STATUS_OK);
    CHECK(config.version == LIBRDP_ADMIN_CONFIG_VERSION);
    CHECK(config.size == sizeof(config));
    CHECK(config.transport == LIBRDP_ADMIN_TRANSPORT_WINRM);
    CHECK(action.version == LIBRDP_ADMIN_ACTION_VERSION);
    CHECK(action.size == sizeof(action));
    CHECK(action.type == LIBRDP_ADMIN_ACTION_LOGOFF);
    CHECK(librdp_admin_new(NULL) == NULL);

    config.endpoint_url = "https://admin.example.test/wsman";
    config.username = username;
    config.password = password;
    config.domain = domain;
    admin = librdp_admin_new(&config);
    CHECK(admin != NULL);
    CHECK(librdp_admin_session_count(admin) == 0);
    CHECK(librdp_admin_session_init(&session) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_session_at(admin, 0, &session) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_admin_clear(admin) == LIBRDP_STATUS_OK);
    action.session_id = 4u;
#if !defined(RDP_HAVE_CURL) || !defined(RDP_HAVE_LIBXML2)
    CHECK(librdp_admin_execute_action(admin, &action) == LIBRDP_STATUS_UNSUPPORTED);
    CHECK(librdp_admin_query_sessions(admin) == LIBRDP_STATUS_UNSUPPORTED);
#endif
    action.type = LIBRDP_ADMIN_ACTION_MESSAGE;
    action.message_text = "bad&command";
    CHECK(librdp_admin_execute_action(admin, &action) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_admin_free(admin);

    CHECK(librdp_admin_config_init(&config) == LIBRDP_STATUS_OK);
    admin = librdp_admin_new(&config);
    CHECK(admin != NULL);
    CHECK(librdp_admin_query_sessions(admin) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_admin_load_sessions_xml(admin, NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_admin_free(admin);
    return 0;
}

/*
 * Coverage: parses synthetic management XML through libxml2 and verifies that
 * failed parses do not destroy the last successful session inventory.
 */
int test_admin_sessions_xml_parse(void)
{
    static const char malformed[] = "<Envelope><Session>";
    librdp_admin_config config;
    librdp_admin_session session;
    librdp_admin* admin = NULL;
    char domain[32];
    char username[32];
    char xml[768];
    int xml_len = 0;

    test_core_fill_secret(domain, sizeof(domain), 241u);
    test_core_fill_secret(username, sizeof(username), 251u);
    xml_len = snprintf(xml,
                       sizeof(xml),
                       "<Envelope><Body><Sessions>"
                       "<Session><SessionId>4</SessionId><UserName>%s</UserName><Domain>%s</Domain>"
                       "<State>Active</State><ClientName>client1</ClientName><WinStationName>rdp-tcp#1</WinStationName>"
                       "<ProtocolName>rdp</ProtocolName></Session>"
                       "<Win32_LogonSession><LogonId>999</LogonId><Status>OK</Status></Win32_LogonSession>"
                       "</Sessions></Body></Envelope>",
                       username,
                       domain);
    CHECK(xml_len > 0 && (size_t)xml_len < sizeof(xml));
    CHECK(librdp_admin_config_init(&config) == LIBRDP_STATUS_OK);
    admin = librdp_admin_new(&config);
    CHECK(admin != NULL);
    CHECK(librdp_admin_load_sessions_xml(admin, xml, (size_t)xml_len) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_session_count(admin) == 2u);

    CHECK(librdp_admin_session_init(&session) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_session_at(admin, 0, &session) == LIBRDP_STATUS_OK);
    CHECK(session.session_id == 4u);
    CHECK(session.username && strcmp(session.username, username) == 0);
    CHECK(session.domain && strcmp(session.domain, domain) == 0);
    CHECK(session.state && strcmp(session.state, "Active") == 0);
    CHECK(session.client_name && strcmp(session.client_name, "client1") == 0);
    CHECK(session.station_name && strcmp(session.station_name, "rdp-tcp#1") == 0);
    CHECK(session.protocol_name && strcmp(session.protocol_name, "rdp") == 0);

    CHECK(librdp_admin_session_init(&session) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_session_at(admin, 1, &session) == LIBRDP_STATUS_OK);
    CHECK(session.logon_id == 999u);
    CHECK(session.state && strcmp(session.state, "OK") == 0);

    CHECK(librdp_admin_load_sessions_xml(admin, malformed, sizeof(malformed) - 1u) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_admin_session_count(admin) == 2u);
    librdp_admin_free(admin);
    return 0;
}

/*
 * Fixture: serves a minimal WinRM SOAP response over loopback HTTP so Admin
 * query coverage does not depend on an external RDS deployment.
 */
static int test_admin_winrm_child(int listen_fd)
{
    char domain[32];
    char request[2048];
    char response[512];
    char header[256];
    char username[32];
    size_t used = 0;
    int client = -1;
    int header_len = 0;
    int response_len = 0;

    test_core_fill_secret(domain, sizeof(domain), 263u);
    test_core_fill_secret(username, sizeof(username), 269u);
    response_len = snprintf(response,
                            sizeof(response),
                            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
                            "<s:Body><Win32_LogonSession><LogonId>77</LogonId><Status>Active</Status>"
                            "<UserName>%s</UserName><Domain>%s</Domain></Win32_LogonSession></s:Body></s:Envelope>",
                            username,
                            domain);
    if (response_len <= 0 || (size_t)response_len >= sizeof(response))
        return 1;
    client = accept(listen_fd, NULL, NULL);
    if (client < 0)
        return 1;
    while (used + 1u < sizeof(request))
    {
        ssize_t got = read(client, request + used, sizeof(request) - used - 1u);

        if (got <= 0)
        {
            close(client);
            return 1;
        }
        used += (size_t)got;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n") && strstr(request, "</s:Envelope>"))
            break;
    }
    if (!strstr(request, "POST /wsman HTTP/") || !strstr(request, "<n:Enumerate/>"))
    {
        close(client);
        return 1;
    }
    header_len = snprintf(header,
                          sizeof(header),
                          "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                          (size_t)response_len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header) ||
        !test_workspace_write_all(client, header, (size_t)header_len) ||
        !test_workspace_write_all(client, response, (size_t)response_len))
    {
        close(client);
        return 1;
    }
    close(client);
    return 0;
}

int test_admin_query_winrm_http(void)
{
    librdp_admin_config config;
    librdp_admin_session session;
    librdp_admin* admin = NULL;
    char domain[32];
    char url[128];
    char username[32];
    uint16_t port = 0;
    int listen_fd = -1;
    pid_t child = -1;
    int child_status = 0;

    test_core_fill_secret(domain, sizeof(domain), 263u);
    test_core_fill_secret(username, sizeof(username), 269u);
    listen_fd = test_workspace_http_listen(&port);
    CHECK(listen_fd >= 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0)
    {
        int rc = test_admin_winrm_child(listen_fd);

        close(listen_fd);
        _exit(rc);
    }
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/wsman", (unsigned)port);
    CHECK(librdp_admin_config_init(&config) == LIBRDP_STATUS_OK);
    config.endpoint_url = url;
    config.timeout_ms = 5000u;
    admin = librdp_admin_new(&config);
    CHECK(admin != NULL);
    CHECK(librdp_admin_query_sessions(admin) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_session_count(admin) == 1u);
    CHECK(librdp_admin_session_init(&session) == LIBRDP_STATUS_OK);
    CHECK(librdp_admin_session_at(admin, 0, &session) == LIBRDP_STATUS_OK);
    CHECK(session.logon_id == 77u);
    CHECK(session.username && strcmp(session.username, username) == 0);
    CHECK(session.domain && strcmp(session.domain, domain) == 0);
    CHECK(session.state && strcmp(session.state, "Active") == 0);
    librdp_admin_free(admin);
    close(listen_fd);
    CHECK(waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Fixture: validates the action path as a Process.Create SOAP request without
 * contacting a real WinRM endpoint. It catches command escaping, request
 * routing and response-code parsing regressions.
 */
static int test_admin_action_winrm_child(int listen_fd)
{
    static const char response[] =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
        "<s:Body><p:Create_OUTPUT "
        "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process\">"
        "<p:ReturnValue>0</p:ReturnValue></p:Create_OUTPUT></s:Body></s:Envelope>";
    char request[3072];
    char header[256];
    size_t used = 0;
    int client = -1;
    int header_len = 0;

    client = accept(listen_fd, NULL, NULL);
    if (client < 0)
        return 1;
    while (used + 1u < sizeof(request))
    {
        ssize_t got = read(client, request + used, sizeof(request) - used - 1u);

        if (got <= 0)
        {
            close(client);
            return 1;
        }
        used += (size_t)got;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n") && strstr(request, "</s:Envelope>"))
            break;
    }
    if (!strstr(request, "POST /wsman HTTP/") ||
        !strstr(request, "Win32_Process/Create") ||
        !strstr(request, "tsdiscon 4"))
    {
        close(client);
        return 1;
    }
    header_len = snprintf(header,
                          sizeof(header),
                          "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                          sizeof(response) - 1u);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header) ||
        !test_workspace_write_all(client, header, (size_t)header_len) ||
        !test_workspace_write_all(client, response, sizeof(response) - 1u))
    {
        close(client);
        return 1;
    }
    close(client);
    return 0;
}

int test_admin_action_winrm_http(void)
{
    librdp_admin_config config;
    librdp_admin_action action;
    librdp_admin* admin = NULL;
    char url[128];
    uint16_t port = 0;
    int listen_fd = -1;
    pid_t child = -1;
    int child_status = 0;

    listen_fd = test_workspace_http_listen(&port);
    CHECK(listen_fd >= 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0)
    {
        int rc = test_admin_action_winrm_child(listen_fd);

        close(listen_fd);
        _exit(rc);
    }
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/wsman", (unsigned)port);
    CHECK(librdp_admin_config_init(&config) == LIBRDP_STATUS_OK);
    config.endpoint_url = url;
    config.timeout_ms = 5000u;
    admin = librdp_admin_new(&config);
    CHECK(admin != NULL);
    CHECK(librdp_admin_action_init(&action) == LIBRDP_STATUS_OK);
    action.type = LIBRDP_ADMIN_ACTION_DISCONNECT;
    action.session_id = 4u;
    action.timeout_ms = 5000u;
    CHECK(librdp_admin_execute_action(admin, &action) == LIBRDP_STATUS_OK);
    librdp_admin_free(admin);
    close(listen_fd);
    CHECK(waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}
