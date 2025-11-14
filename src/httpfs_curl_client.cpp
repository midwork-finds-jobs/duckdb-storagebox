#include "http_state.hpp"
#include "httpfs_client.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "duckdb/common/exception/http_exception.hpp"
#include <curl/curl.h>
#include <sys/stat.h>

#ifndef EMSCRIPTEN
#include "httpfs_curl_client.hpp"
#endif

namespace duckdb {

// we statically compile in libcurl, which means the cert file location of the
// build machine is the place curl will look. But not every distro has this file
// in the same location, so we search a number of common locations and use the
// first one we find.
static std::string certFileLocations[] = {
    // Arch, Debian-based, Gentoo
    "/etc/ssl/certs/ca-certificates.crt",
    // RedHat 7 based
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // Redhat 6 based
    "/etc/pki/tls/certs/ca-bundle.crt",
    // OpenSUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine
    "/etc/ssl/cert.pem"};

//! Grab the first path that exists, from a list of well-known locations
static std::string SelectCURLCertPath() {
  for (std::string &caFile : certFileLocations) {
    struct stat buf;
    if (stat(caFile.c_str(), &buf) == 0) {
      return caFile;
    }
  }
  return std::string();
}

static std::string cert_path = SelectCURLCertPath();

struct RequestInfo {
  string url = "";
  string body = "";
  uint16_t response_code = 0;
  std::vector<HTTPHeaders> header_collection;
  // For custom HTTP methods with body
  string read_buffer = "";
  size_t read_position = 0;
  // For streaming uploads from file
  FILE *upload_file = nullptr;
  size_t upload_file_size = 0;
};

static size_t RequestWriteCallback(void *contents, size_t size, size_t nmemb,
                                   void *userp) {
  size_t totalSize = size * nmemb;
  std::string *str = static_cast<std::string *>(userp);
  str->append(static_cast<char *>(contents), totalSize);
  return totalSize;
}

static size_t ReadCallbackCustom(char *buffer, size_t size, size_t nitems,
                                 void *userp) {
  RequestInfo *info = static_cast<RequestInfo *>(userp);
  size_t max_bytes = size * nitems;
  size_t remaining = info->read_buffer.size() - info->read_position;
  size_t to_copy = (max_bytes < remaining) ? max_bytes : remaining;

  if (to_copy > 0) {
    memcpy(buffer, info->read_buffer.data() + info->read_position, to_copy);
    info->read_position += to_copy;
  }

  fprintf(stderr,
          "[CURL ReadCallback] Sending %zu bytes (position=%zu, total=%zu)\n",
          to_copy, info->read_position, info->read_buffer.size());
  fflush(stderr);

  return to_copy;
}

static size_t ReadCallbackFile(char *buffer, size_t size, size_t nitems,
                               void *userp) {
  RequestInfo *info = static_cast<RequestInfo *>(userp);
  size_t max_bytes = size * nitems;

  if (!info->upload_file) {
    return 0; // EOF
  }

  size_t bytes_read = fread(buffer, 1, max_bytes, info->upload_file);

  return bytes_read; // Return 0 on EOF or error
}

static size_t RequestHeaderCallback(void *contents, size_t size, size_t nmemb,
                                    void *userp) {
  size_t totalSize = size * nmemb;
  std::string header(static_cast<char *>(contents), totalSize);
  HeaderCollector *header_collection = static_cast<HeaderCollector *>(userp);

  // Trim trailing \r\n
  if (!header.empty() && header.back() == '\n') {
    header.pop_back();
    if (!header.empty() && header.back() == '\r') {
      header.pop_back();
    }
  }

  // If header starts with HTTP/... curl has followed a redirect and we have a
  // new Header, so we push back a new header_collection and store headers from
  // the redirect there.
  if (header.rfind("HTTP/", 0) == 0) {
    header_collection->header_collection.push_back(HTTPHeaders());
    header_collection->header_collection.back().Insert("__RESPONSE_STATUS__",
                                                       header);
  }

  size_t colonPos = header.find(':');

  if (colonPos != std::string::npos) {
    // Split the string into two parts
    std::string part1 = header.substr(0, colonPos);
    std::string part2 = header.substr(colonPos + 1);
    if (part2.at(0) == ' ') {
      part2.erase(0, 1);
    }

    header_collection->header_collection.back().Insert(part1, part2);
  }
  // TODO: log headers that don't follow the header format

  return totalSize;
}

CURLHandle::CURLHandle(const string &token, const string &cert_path) {
  curl = curl_easy_init();
  if (!curl) {
    throw InternalException("Failed to initialize curl");
  }
  if (!token.empty()) {
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
  }
  if (!cert_path.empty()) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, cert_path.c_str());
  }
}

CURLHandle::~CURLHandle() { curl_easy_cleanup(curl); }

static idx_t httpfs_client_count = 0;

class HTTPFSCurlClient : public HTTPClient {
public:
  HTTPFSCurlClient(HTTPFSParams &http_params, const string &proto_host_port) {
    fprintf(stderr,
            "[CURL CLIENT] HTTPFSCurlClient constructor called for "
            "proto_host_port=%s\n",
            proto_host_port.c_str());
    fflush(stderr);
    auto bearer_token = "";
    if (!http_params.bearer_token.empty()) {
      bearer_token = http_params.bearer_token.c_str();
    }
    state = http_params.state;

    // call curl_global_init if not already done by another HTTPFS Client
    InitCurlGlobal();

    curl = make_uniq<CURLHandle>(bearer_token, SelectCURLCertPath());
    request_info = make_uniq<RequestInfo>();

    // set curl options
    // follow redirects
    curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Curl re-uses connections by default
    if (!http_params.keep_alive) {
      curl_easy_setopt(*curl, CURLOPT_FORBID_REUSE, 1L);
    }

    if (http_params.enable_curl_server_cert_verification) {
      curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYPEER, 1L); // Verify the cert
      curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYHOST,
                       2L); // Verify that the cert matches the hostname
    } else {
      curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYPEER,
                       0L); // Override default, don't verify the cert
      curl_easy_setopt(*curl, CURLOPT_SSL_VERIFYHOST,
                       0L); // Override default, don't verify that the cert
                            // matches the hostname
    }

    // set read timeout
    curl_easy_setopt(*curl, CURLOPT_TIMEOUT, http_params.timeout);
    // set connection timeout
    curl_easy_setopt(*curl, CURLOPT_CONNECTTIMEOUT, http_params.timeout);
    // accept content as-is (i.e no decompressing)
    curl_easy_setopt(*curl, CURLOPT_ACCEPT_ENCODING, "identity");
    // follow redirects
    curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

    // define the header callback
    curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, RequestHeaderCallback);
    curl_easy_setopt(*curl, CURLOPT_HEADERDATA,
                     &request_info->header_collection);
    // define the write data callback (for get requests)
    curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, RequestWriteCallback);
    curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &request_info->body);

    if (!http_params.http_proxy.empty()) {
      curl_easy_setopt(*curl, CURLOPT_PROXY,
                       StringUtil::Format("%s:%s", http_params.http_proxy,
                                          http_params.http_proxy_port)
                           .c_str());

      if (!http_params.http_proxy_username.empty()) {
        curl_easy_setopt(*curl, CURLOPT_PROXYUSERNAME,
                         http_params.http_proxy_username.c_str());
        curl_easy_setopt(*curl, CURLOPT_PROXYPASSWORD,
                         http_params.http_proxy_password.c_str());
      }
    }
  }

  ~HTTPFSCurlClient() { DestroyCurlGlobal(); }

  void Initialize(HTTPParams &http_params) {
    // All initialization is done in the constructor for now
    // This method is required by DuckDB 1.4.2+ HTTPClient interface
  }

  unique_ptr<HTTPResponse> Get(GetRequestInfo &info) override {
    if (state) {
      state->get_count++;
    }

    auto curl_headers = TransformHeadersCurl(info.headers);
    request_info->url = info.url;
    if (!info.params.extra_headers.empty()) {
      auto curl_params = TransformParamsCurl(info.params);
      request_info->url += "?" + curl_params;
    }

    CURLcode res;
    {
      // If the same handle served a HEAD request, we must set NOBODY back to 0L
      // to request content again
      curl_easy_setopt(*curl, CURLOPT_NOBODY, 0L);
      curl_easy_setopt(*curl, CURLOPT_URL, request_info->url.c_str());
      curl_easy_setopt(*curl, CURLOPT_HTTPHEADER,
                       curl_headers ? curl_headers.headers : nullptr);
      res = curl->Execute();
    }

    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE,
                      &request_info->response_code);

    idx_t bytes_received = 0;
    if (!request_info->header_collection.empty() &&
        request_info->header_collection.back().HasHeader("content-length")) {
      bytes_received =
          std::stoi(request_info->header_collection.back().GetHeaderValue(
              "content-length"));
      D_ASSERT(bytes_received == request_info->body.size());
    } else {
      bytes_received = request_info->body.size();
    }
    if (state) {
      state->total_bytes_received += bytes_received;
    }

    const char *data = request_info->body.c_str();
    if (info.content_handler) {
      info.content_handler(const_data_ptr_cast(data), bytes_received);
    }

    return TransformResponseCurl(res);
  }

  unique_ptr<HTTPResponse> Put(PutRequestInfo &info) override {
    if (state) {
      state->put_count++;
      state->total_bytes_sent += info.buffer_in_len;
    }

    auto curl_headers = TransformHeadersCurl(info.headers);
    // Add content type header from info
    curl_headers.Add("Content-Type: " + info.content_type);

    // Disable "Expect: 100-continue" for large uploads to avoid HTTP 100
    // Continue errors Some WebDAV servers (like Hetzner Storage Box) don't
    // handle this well for large files
    constexpr idx_t LARGE_UPLOAD_THRESHOLD = 10 * 1024 * 1024; // 10 MB
    bool is_large_upload = false;
    if (info.buffer_in_len > LARGE_UPLOAD_THRESHOLD) {
      is_large_upload = true;
      curl_headers.Add("Expect:");
      fprintf(stderr,
              "[CURL PUT] Disabled Expect: 100-continue for large upload (%llu "
              "bytes)\n",
              (unsigned long long)info.buffer_in_len);
      fflush(stderr);
    }

    // transform parameters
    request_info->url = info.url;
    if (!info.params.extra_headers.empty()) {
      auto curl_params = TransformParamsCurl(info.params);
      request_info->url += "?" + curl_params;
    }

    CURLcode res;
    {
      curl_easy_setopt(*curl, CURLOPT_URL, request_info->url.c_str());
      // Perform PUT
      curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "PUT");

      // Check if we're streaming from a file (for large uploads)
      if (request_info->upload_file) {
        fprintf(stderr,
                "[CURL PUT] Using streaming upload from file (%llu bytes)\n",
                (unsigned long long)request_info->upload_file_size);
        // Use read callback for streaming
        curl_easy_setopt(*curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(*curl, CURLOPT_READFUNCTION, ReadCallbackFile);
        curl_easy_setopt(*curl, CURLOPT_READDATA, request_info.get());
        curl_easy_setopt(*curl, CURLOPT_INFILESIZE_LARGE,
                         (curl_off_t)request_info->upload_file_size);
      } else {
        // Include PUT body from memory
        curl_easy_setopt(*curl, CURLOPT_POSTFIELDS,
                         const_char_ptr_cast(info.buffer_in));
        curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);
      }

      // For large uploads, increase the timeout to 10 minutes (600 seconds)
      // Default is 30 seconds which is too short for multi-hundred MB files
      if (is_large_upload) {
        constexpr uint64_t LARGE_UPLOAD_TIMEOUT = 600; // 10 minutes
        curl_easy_setopt(*curl, CURLOPT_TIMEOUT, LARGE_UPLOAD_TIMEOUT);
        fprintf(stderr,
                "[CURL PUT] Set timeout to %llu seconds for large upload\n",
                (unsigned long long)LARGE_UPLOAD_TIMEOUT);
        fflush(stderr);
      }

      // Apply headers
      curl_easy_setopt(*curl, CURLOPT_HTTPHEADER,
                       curl_headers ? curl_headers.headers : nullptr);

      res = curl->Execute();
    }

    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE,
                      &request_info->response_code);

    return TransformResponseCurl(res);
  }

  unique_ptr<HTTPResponse> Head(HeadRequestInfo &info) override {
    if (state) {
      state->head_count++;
    }

    auto curl_headers = TransformHeadersCurl(info.headers);
    request_info->url = info.url;
    // transform parameters
    if (!info.params.extra_headers.empty()) {
      auto curl_params = TransformParamsCurl(info.params);
      request_info->url += "?" + curl_params;
    }

    CURLcode res;
    {
      // Set URL
      curl_easy_setopt(*curl, CURLOPT_URL, request_info->url.c_str());

      // Perform HEAD request instead of GET
      curl_easy_setopt(*curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(*curl, CURLOPT_HTTPGET, 0L);

      // Add headers if any
      curl_easy_setopt(*curl, CURLOPT_HTTPHEADER,
                       curl_headers ? curl_headers.headers : nullptr);

      // Execute HEAD request
      res = curl->Execute();
    }

    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE,
                      &request_info->response_code);
    return TransformResponseCurl(res);
  }

  unique_ptr<HTTPResponse> Delete(DeleteRequestInfo &info) override {
    if (state) {
      state->delete_count++;
    }

    auto curl_headers = TransformHeadersCurl(info.headers);
    // transform parameters
    request_info->url = info.url;
    if (!info.params.extra_headers.empty()) {
      auto curl_params = TransformParamsCurl(info.params);
      request_info->url += "?" + curl_params;
    }

    CURLcode res;
    {
      // Set URL
      curl_easy_setopt(*curl, CURLOPT_URL, request_info->url.c_str());

      // Set DELETE request method
      curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, "DELETE");

      // Follow redirects
      curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

      // Add headers if any
      curl_easy_setopt(*curl, CURLOPT_HTTPHEADER,
                       curl_headers ? curl_headers.headers : nullptr);

      // Execute DELETE request
      res = curl->Execute();
    }

    // Get HTTP response status code
    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE,
                      &request_info->response_code);
    return TransformResponseCurl(res);
  }

  unique_ptr<HTTPResponse> Post(PostRequestInfo &info) override {
    fprintf(stderr, "[CURL] Post() called: url=%s\n", info.url.c_str());
    fflush(stderr);
    if (state) {
      state->post_count++;
      state->total_bytes_sent += info.buffer_in_len;
    }

    auto curl_headers = TransformHeadersCurl(info.headers);
    const string content_type = "Content-Type: application/octet-stream";
    curl_headers.Add(content_type.c_str());

    // Disable "Expect: 100-continue" for large uploads to avoid HTTP 100
    // Continue errors Some WebDAV servers (like Hetzner Storage Box) don't
    // handle this well for large files
    constexpr idx_t LARGE_UPLOAD_THRESHOLD = 10 * 1024 * 1024; // 10 MB
    if (info.buffer_in_len > LARGE_UPLOAD_THRESHOLD) {
      curl_headers.Add("Expect:");
      fprintf(stderr,
              "[CURL] Disabled Expect: 100-continue for large upload (%llu "
              "bytes)\n",
              (unsigned long long)info.buffer_in_len);
      fflush(stderr);
    }

    // Check if a custom HTTP method is specified (e.g., MKCOL, PROPFIND for
    // WebDAV)
    string custom_method;
    auto method_it = info.params.extra_headers.find("X-DuckDB-HTTP-Method");
    if (method_it != info.params.extra_headers.end()) {
      custom_method = method_it->second;
    }

    // Transform parameters (excluding X-DuckDB-HTTP-Method which is a
    // directive, not a URL param)
    request_info->url = info.url;
    if (!info.params.extra_headers.empty()) {
      auto curl_params = TransformParamsCurl(info.params);
      if (!curl_params.empty()) {
        request_info->url += "?" + curl_params;
      }
    }

    fprintf(stderr, "[CURL] Final URL: %s, Custom method: %s\n",
            request_info->url.c_str(),
            custom_method.empty() ? "(none)" : custom_method.c_str());
    fflush(stderr);

    CURLcode res;
    {
      // Set URL
      curl_easy_setopt(*curl, CURLOPT_URL, request_info->url.c_str());

      // Handle custom methods (like WebDAV MKCOL, PROPFIND) similar to DELETE
      if (!custom_method.empty()) {
        // Set custom request method (this will NOT trigger POST mode)
        curl_easy_setopt(*curl, CURLOPT_CUSTOMREQUEST, custom_method.c_str());

        // If there's a request body, set it using POSTFIELDS
        // Despite the name, POSTFIELDS works with CUSTOMREQUEST
        if (info.buffer_in && info.buffer_in_len > 0) {
          curl_easy_setopt(*curl, CURLOPT_POSTFIELDS,
                           const_char_ptr_cast(info.buffer_in));
          curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);
        }

        fprintf(stderr,
                "[CURL] Using CUSTOMREQUEST: %s with body length: %llu\n",
                custom_method.c_str(), (unsigned long long)info.buffer_in_len);
        fflush(stderr);
      } else {
        // Regular POST
        curl_easy_setopt(*curl, CURLOPT_POST, 1L);
        if (info.buffer_in && info.buffer_in_len > 0) {
          curl_easy_setopt(*curl, CURLOPT_POSTFIELDS,
                           const_char_ptr_cast(info.buffer_in));
          curl_easy_setopt(*curl, CURLOPT_POSTFIELDSIZE, info.buffer_in_len);
        }
      }

      // Follow redirects
      curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);

      // Add headers if any
      curl_easy_setopt(*curl, CURLOPT_HTTPHEADER,
                       curl_headers ? curl_headers.headers : nullptr);

      // Execute request
      res = curl->Execute();
    }

    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE,
                      &request_info->response_code);
    info.buffer_out = request_info->body;
    // Construct HTTPResponse
    return TransformResponseCurl(res);
  }

private:
  CURLRequestHeaders TransformHeadersCurl(const HTTPHeaders &header_map) {
    std::vector<std::string> headers;
    for (auto &entry : header_map) {
      const std::string new_header = entry.first + ": " + entry.second;
      headers.push_back(new_header);
    }
    CURLRequestHeaders curl_headers;
    for (auto &header : headers) {
      curl_headers.Add(header);
    }
    return curl_headers;
  }

  string TransformParamsCurl(const HTTPParams &params) {
    string result = "";
    unordered_map<string, string> escaped_params;
    bool first_param = true;
    for (auto &entry : params.extra_headers) {
      const string key = entry.first;
      // Skip X-DuckDB-HTTP-Method as it's a directive, not a URL param
      if (key == "X-DuckDB-HTTP-Method") {
        continue;
      }
      const string value = curl_easy_escape(*curl, entry.second.c_str(), 0);
      if (!first_param) {
        result += "&";
      }
      result += key + "=" + value;
      first_param = false;
    }
    return result;
  }

  void ResetRequestInfo() {
    // clear headers after transform
    request_info->header_collection.clear();
    // reset request info.
    request_info->body = "";
    request_info->url = "";
    request_info->response_code = 0;
    // reset upload file for streaming
    request_info->upload_file = nullptr;
    request_info->upload_file_size = 0;
  }

  unique_ptr<HTTPResponse> TransformResponseCurl(CURLcode res) {
    auto status_code = HTTPStatusCode(request_info->response_code);
    auto response = make_uniq<HTTPResponse>(status_code);
    if (res != CURLcode::CURLE_OK) {
      // TODO: request error can come from HTTPS Status code toString() value.
      if (!request_info->header_collection.empty() &&
          request_info->header_collection.back().HasHeader(
              "__RESPONSE_STATUS__")) {
        response->request_error =
            request_info->header_collection.back().GetHeaderValue(
                "__RESPONSE_STATUS__");
      } else {
        response->request_error = curl_easy_strerror(res);
      }
      return response;
    }
    response->body = request_info->body;
    response->url = request_info->url;
    if (!request_info->header_collection.empty()) {
      for (auto &header : request_info->header_collection.back()) {
        response->headers.Insert(header.first, header.second);
      }
    }
    ResetRequestInfo();
    return response;
  }

private:
  unique_ptr<CURLHandle> curl;
  optional_ptr<HTTPState> state;
  unique_ptr<RequestInfo> request_info;

  // Friend function for streaming upload support
  friend void SetHTTPClientUploadFile(HTTPClient *client, FILE *fp,
                                      size_t size);

  static std::mutex &GetRefLock() {
    static std::mutex mtx;
    return mtx;
  }

  static void InitCurlGlobal() {
    GetRefLock();
    if (httpfs_client_count == 0) {
      curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    ++httpfs_client_count;
  }

  static void DestroyCurlGlobal() {
    // TODO: when to call curl_global_cleanup()
    // calling it on client destruction causes SSL errors when verification is
    // on (due to many requests). GetRefLock(); if (httpfs_client_count == 0) {
    // 	throw InternalException("Destroying Httpfs client that did not
    // initialize CURL");
    // }
    // --httpfs_client_count;
    // if (httpfs_client_count == 0) {
    // 	curl_global_cleanup();
    // }
  }
};

unique_ptr<HTTPClient>
HTTPFSCurlUtil::InitializeClient(HTTPParams &http_params,
                                 const string &proto_host_port) {
  auto client = make_uniq<HTTPFSCurlClient>(http_params.Cast<HTTPFSParams>(),
                                            proto_host_port);
  return std::move(client);
}

unordered_map<string, string>
HTTPFSCurlUtil::ParseGetParameters(const string &text) {
  unordered_map<std::string, std::string> params;

  auto pos = text.find('?');
  if (pos == std::string::npos)
    return params;

  std::string query = text.substr(pos + 1);
  std::stringstream ss(query);
  std::string item;

  while (std::getline(ss, item, '&')) {
    auto eq_pos = item.find('=');
    if (eq_pos != std::string::npos) {
      std::string key = item.substr(0, eq_pos);
      std::string value = StringUtil::URLDecode(item.substr(eq_pos + 1));
      params[key] = value;
    } else {
      params[item] = ""; // key with no value
    }
  }

  return params;
}

string HTTPFSCurlUtil::GetName() const { return "HTTPFS-Curl"; }

// Helper function to set upload file for streaming - callable from other
// modules
void SetHTTPClientUploadFile(HTTPClient *client, FILE *fp, size_t size) {
  auto *curl_client = dynamic_cast<HTTPFSCurlClient *>(client);
  if (curl_client && curl_client->request_info) {
    curl_client->request_info->upload_file = fp;
    curl_client->request_info->upload_file_size = size;
  }
}

} // namespace duckdb
