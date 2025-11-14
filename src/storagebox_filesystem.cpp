#include "storagebox_filesystem.hpp"

#include "crypto.hpp"
#include "duckdb.hpp"
#ifndef DUCKDB_AMALGAMATION
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/logging/log_type.hpp"
#include "http_state.hpp"
#endif

#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar/string_common.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "httpfs_client.hpp"
#include "httpfs_curl_client.hpp"

#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace duckdb {

StorageBoxFileHandle::~StorageBoxFileHandle() {
  // Nothing to clean up - chunks are uploaded directly via SFTP
}

void StorageBoxFileHandle::TryCombineReadyChunks() {
  // Only one thread should combine at a time
  std::unique_lock<std::mutex> combine_lock(combine_mutex, std::try_to_lock);
  if (!combine_lock.owns_lock()) {
    // Another thread is already combining, skip
    return;
  }

  auto &storagebox_fs = dynamic_cast<StorageBoxFileSystem &>(file_system);
  auto params = storagebox_fs.ParseSSHParams(original_url, file_opener);

  // Keep combining consecutive ready chunks
  while (true) {
    size_t chunk_to_combine;
    bool chunk_ready;

    {
      std::lock_guard<std::mutex> upload_lock(upload_mutex);
      chunk_to_combine = next_chunk_to_combine;
      chunk_ready = chunk_to_combine < chunks_uploaded.size() &&
                    chunks_uploaded[chunk_to_combine];
    }

    if (!chunk_ready) {
      // No more consecutive chunks ready
      break;
    }

    // Combine this chunk
    try {
      auto ssh_client =
          storagebox_fs.GetOrCreateSSHClient(original_url, file_opener);

      string part_path =
          params.remote_path + ".part." + std::to_string(chunk_to_combine);
      string dd_cmd;

      if (chunk_to_combine == 0) {
        // First chunk: create the output file
        dd_cmd =
            "dd if=" + part_path + " of=" + params.remote_path + " status=none";
      } else {
        // Subsequent chunks: append to output file
        dd_cmd = "dd if=" + part_path + " of=" + params.remote_path +
                 " oflag=append conv=notrunc status=none";
      }

      fprintf(stderr,
              "[StorageBox] TryCombineReadyChunks: combining chunk #%zu: %s\n",
              chunk_to_combine, dd_cmd.c_str());
      ssh_client->ExecuteCommand(dd_cmd);

      // Delete the part file immediately after combining
      string rm_cmd = "rm " + part_path;
      try {
        ssh_client->ExecuteCommand(rm_cmd);
      } catch (const std::exception &e) {
        fprintf(stderr, "[StorageBox] Warning: failed to delete %s: %s\n",
                part_path.c_str(), e.what());
      }

      // Increment next_chunk_to_combine
      {
        std::lock_guard<std::mutex> upload_lock(upload_mutex);
        next_chunk_to_combine++;
      }

      fprintf(stderr,
              "[StorageBox] TryCombineReadyChunks: successfully combined chunk "
              "#%zu, next=%zu\n",
              chunk_to_combine, next_chunk_to_combine);

    } catch (const std::exception &e) {
      fprintf(
          stderr,
          "[StorageBox] TryCombineReadyChunks: failed to combine chunk #%zu: "
          "%s\n",
          chunk_to_combine, e.what());
      // Don't throw - we'll try again in WaitForPendingUploads/Close
      break;
    }
  }
}

void StorageBoxFileHandle::WaitForPendingUploads() {
  fprintf(
      stderr,
      "[StorageBox] WaitForPendingUploads: waiting for %zu pending uploads\n",
      pending_uploads.size());

  std::vector<std::future<void>> uploads_to_wait;
  {
    std::lock_guard<std::mutex> lock(upload_mutex);
    uploads_to_wait = std::move(pending_uploads);
    pending_uploads.clear();
  }

  // Wait for all async uploads to complete and check for errors
  for (size_t i = 0; i < uploads_to_wait.size(); i++) {
    try {
      uploads_to_wait[i].get(); // This will throw if the async operation failed
    } catch (const std::exception &e) {
      fprintf(stderr,
              "[StorageBox] WaitForPendingUploads: Upload %zu failed: %s\n", i,
              e.what());
      throw IOException("Async chunk upload failed: %s", e.what());
    }
  }

  fprintf(stderr,
          "[StorageBox] WaitForPendingUploads: all %zu uploads completed "
          "successfully\n",
          uploads_to_wait.size());
}

void StorageBoxFileHandle::Close() {
  fprintf(stderr,
          "[StorageBox] Close called for: %s (chunks: %zu, total: %zu bytes)\n",
          path.c_str(), chunk_count, total_bytes_uploaded);

  FlushBuffer(); // Flush any remaining buffered data

  // Wait for all pending async uploads to complete
  WaitForPendingUploads();

  // Combine any remaining chunks that weren't combined progressively
  size_t start_chunk = next_chunk_to_combine;
  if (start_chunk < chunk_count) {
    auto &storagebox_fs = dynamic_cast<StorageBoxFileSystem &>(file_system);
    auto parsed_url = storagebox_fs.ParseUrl(path);

    fprintf(stderr,
            "[StorageBox] Close: combining remaining %zu chunks (from #%zu)\n",
            chunk_count - start_chunk, start_chunk);

    try {
      auto ssh_client =
          storagebox_fs.GetOrCreateSSHClient(original_url, file_opener);
      auto params = storagebox_fs.ParseSSHParams(original_url, file_opener);

      // Use dd to combine remaining parts into final file
      for (size_t i = start_chunk; i < chunk_count; i++) {
        string part_path = params.remote_path + ".part." + std::to_string(i);
        string dd_cmd;

        if (i == 0) {
          // First part: create the output file
          dd_cmd = "dd if=" + part_path + " of=" + params.remote_path +
                   " status=none";
        } else {
          // Subsequent parts: append to output file
          dd_cmd = "dd if=" + part_path + " of=" + params.remote_path +
                   " oflag=append conv=notrunc status=none";
        }

        fprintf(stderr, "[StorageBox] Close: executing: %s\n", dd_cmd.c_str());
        ssh_client->ExecuteCommand(dd_cmd);
      }

      // Delete part files
      for (size_t i = 0; i < chunk_count; i++) {
        string part_path = params.remote_path + ".part." + std::to_string(i);
        string rm_cmd = "rm " + part_path;
        try {
          ssh_client->ExecuteCommand(rm_cmd);
        } catch (const std::exception &e) {
          fprintf(stderr, "[StorageBox] Warning: failed to delete %s: %s\n",
                  part_path.c_str(), e.what());
        }
      }

      fprintf(stderr, "[StorageBox] Close: successfully combined %zu chunks\n",
              chunk_count);

    } catch (const std::exception &e) {
      fprintf(stderr, "[StorageBox] Close: failed to combine chunks: %s\n",
              e.what());
      throw IOException("Failed to combine chunks for file %s: %s",
                        path.c_str(), e.what());
    }
  } else if (chunk_count == 1 && next_chunk_to_combine == 0) {
    // Single chunk that wasn't combined progressively: rename .part.0 to final
    // filename
    auto &storagebox_fs = dynamic_cast<StorageBoxFileSystem &>(file_system);
    auto parsed_url = storagebox_fs.ParseUrl(path);

    try {
      auto ssh_client =
          storagebox_fs.GetOrCreateSSHClient(original_url, file_opener);
      auto params = storagebox_fs.ParseSSHParams(original_url, file_opener);

      string part_path = params.remote_path + ".part.0";
      string mv_cmd = "mv " + part_path + " " + params.remote_path;

      fprintf(stderr, "[StorageBox] Close: renaming single chunk: %s\n",
              mv_cmd.c_str());
      ssh_client->ExecuteCommand(mv_cmd);

    } catch (const std::exception &e) {
      fprintf(stderr, "[StorageBox] Close: failed to rename chunk: %s\n",
              e.what());
      throw IOException("Failed to rename chunk for file %s: %s", path.c_str(),
                        e.what());
    }
  }
}

void StorageBoxFileHandle::FlushBuffer() {
  if (!buffer_dirty || write_buffer.empty()) {
    fprintf(stderr, "[StorageBox] FlushBuffer: nothing to flush\n");
    return;
  }

  auto &storagebox_fs = dynamic_cast<StorageBoxFileSystem &>(file_system);
  auto parsed_url = storagebox_fs.ParseUrl(path);

  // Create parent directory if this is the first chunk (must be done
  // synchronously)
  if (chunk_count == 0) {
    auto last_slash = path.rfind('/');
    if (last_slash != string::npos) {
      string dir_path = path.substr(0, last_slash);
      try {
        storagebox_fs.CreateDirectoryRecursive(dir_path);
      } catch (const std::exception &e) {
        fprintf(stderr, "[StorageBox] Warning: mkdir failed: %s\n", e.what());
      }
    }
  }

  // Copy buffer data and metadata for async upload
  string buffer_copy = write_buffer;
  size_t buffer_size = buffer_copy.size();
  size_t current_chunk_number;

  {
    std::lock_guard<std::mutex> lock(upload_mutex);
    current_chunk_number = chunk_count;
    chunk_count++;
    total_bytes_uploaded += buffer_size;
  }

  // Build URLs for upload
  string part_file_path =
      parsed_url.path + ".part." + std::to_string(current_chunk_number);
  string part_http_url =
      parsed_url.http_proto + "://" + parsed_url.host + part_file_path;

  fprintf(stderr,
          "[StorageBox] FlushBuffer: starting async upload of chunk #%zu (%zu "
          "bytes) to %s\n",
          current_chunk_number + 1, buffer_size, part_file_path.c_str());

  // Ensure chunks_uploaded vector is large enough
  {
    std::lock_guard<std::mutex> lock(upload_mutex);
    if (chunks_uploaded.size() <= current_chunk_number) {
      chunks_uploaded.resize(current_chunk_number + 1, false);
    }
  }

  // Launch async HTTP PUT upload
  auto upload_future = std::async(std::launch::async, [&storagebox_fs, this,
                                                       part_http_url,
                                                       buffer_copy, buffer_size,
                                                       current_chunk_number]() {
    try {
      HTTPHeaders headers;
      auto response = storagebox_fs.PutRequest(
          *this, part_http_url, headers, const_cast<char *>(buffer_copy.data()),
          buffer_size, "");

      if (response->status != HTTPStatusCode::OK_200 &&
          response->status != HTTPStatusCode::Created_201 &&
          response->status != HTTPStatusCode::NoContent_204) {
        throw IOException("Failed to upload chunk: HTTP %d",
                          static_cast<int>(response->status));
      }

      fprintf(stderr,
              "[StorageBox] FlushBuffer: async upload of chunk #%zu completed "
              "successfully\n",
              current_chunk_number + 1);

      // Mark chunk as uploaded and try combining ready chunks
      {
        std::lock_guard<std::mutex> lock(upload_mutex);
        chunks_uploaded[current_chunk_number] = true;
      }

      // Try to combine chunks progressively as they become ready
      TryCombineReadyChunks();

    } catch (const std::exception &e) {
      fprintf(
          stderr,
          "[StorageBox] FlushBuffer: async upload of chunk #%zu failed: %s\n",
          current_chunk_number + 1, e.what());
      throw;
    }
  });

  // Store future for later synchronization
  {
    std::lock_guard<std::mutex> lock(upload_mutex);
    pending_uploads.push_back(std::move(upload_future));
  }

  // Clear the buffer immediately so DuckDB can continue writing
  write_buffer.clear();
  buffer_dirty = false;

  fprintf(stderr,
          "[StorageBox] FlushBuffer: buffer cleared, DuckDB can continue "
          "writing (pending uploads: %zu)\n",
          pending_uploads.size());
}

void StorageBoxFileHandle::Initialize(optional_ptr<FileOpener> opener) {
  HTTPFileHandle::Initialize(opener);
  file_opener = opener; // Store for SSH operations in Close()
  // Store original URL (from file.path before conversion to https://)
  // We can reconstruct it from path by checking if it starts with https://
  // and extracting the username from auth_params
}

unique_ptr<HTTPClient> StorageBoxFileHandle::CreateClient() {
  fprintf(stderr, "[StorageBox] CreateClient called, http_util name: %s\n",
          http_params.http_util.GetName().c_str());
  fflush(stderr);
  auto client = http_params.http_util.InitializeClient(http_params, path);
  fprintf(stderr, "[StorageBox] CreateClient returned client: %p\n",
          (void *)client.get());
  fflush(stderr);
  return client;
}

StorageBoxAuthParams
StorageBoxAuthParams::ReadFrom(optional_ptr<FileOpener> opener,
                               FileOpenerInfo &info) {
  StorageBoxAuthParams params;

  if (!opener) {
    return params;
  }

  KeyValueSecretReader secret_reader(*opener, &info, "storagebox");
  secret_reader.TryGetSecretKey("username", params.username);
  secret_reader.TryGetSecretKey("password", params.password);

  return params;
}

string ParsedStorageBoxUrl::GetHTTPUrl() const {
  return http_proto + "://" + host + path;
}

ParsedStorageBoxUrl StorageBoxFileSystem::ParseUrl(const string &url) {
  ParsedStorageBoxUrl result;

  // Check for storagebox:// protocol (Hetzner Storage Box shorthand)
  if (StringUtil::StartsWith(url, "storagebox://")) {
    result.http_proto = "https";
    // Extract username and path from storagebox://u123456/path/to/file
    string remainder = url.substr(13); // Skip "storagebox://"

    auto slash_pos = remainder.find('/');
    string username;
    if (slash_pos != string::npos) {
      username = remainder.substr(0, slash_pos);
      result.path = remainder.substr(slash_pos);
    } else {
      username = remainder;
      result.path = "/";
    }

    // Build the Hetzner Storage Box hostname
    result.host = username + ".your-storagebox.de";
    return result;
  }

  // Only support https:// and http:// (after storagebox:// has been converted)
  if (StringUtil::StartsWith(url, "https://")) {
    result.http_proto = "https";
    result.host = url.substr(8);
  } else if (StringUtil::StartsWith(url, "http://")) {
    result.http_proto = "http";
    result.host = url.substr(7);
  } else {
    throw IOException(
        "Invalid StorageBox URL: %s (only storagebox:// protocol is supported)",
        url);
  }

  // Split host and path
  auto slash_pos = result.host.find('/');
  if (slash_pos != string::npos) {
    result.path = result.host.substr(slash_pos);
    result.host = result.host.substr(0, slash_pos);
  } else {
    result.path = "/";
  }

  return result;
}

string StorageBoxFileSystem::Base64Encode(const string &input) {
  const string base64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  string result;
  int val = 0;
  int valb = -6;

  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      result.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }

  if (valb > -6) {
    result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  }

  while (result.size() % 4) {
    result.push_back('=');
  }

  return result;
}

// Custom HTTP request using HTTP client infrastructure
duckdb::unique_ptr<HTTPResponse> StorageBoxFileSystem::CustomRequest(
    FileHandle &handle, string url, HTTPHeaders header_map,
    const string &method, char *buffer_in, idx_t buffer_in_len) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();

  fprintf(stderr, "[StorageBox] CustomRequest called: method=%s, url=%s\n",
          method.c_str(), url.c_str());

  // Store the method in extra headers as a hint for custom processing
  auto &http_params = wfh.http_params;
  auto original_extra_headers = http_params.extra_headers;
  http_params.extra_headers["X-DuckDB-HTTP-Method"] = method;

  fprintf(stderr, "[StorageBox] CustomRequest: Set X-DuckDB-HTTP-Method=%s\n",
          method.c_str());
  fprintf(stderr, "[StorageBox] CustomRequest: extra_headers size=%zu\n",
          http_params.extra_headers.size());

  // Get the HTTP client and call Post() directly
  fprintf(stderr, "[StorageBox] CustomRequest: Getting HTTP client\n");
  fflush(stderr);
  auto client = wfh.GetClient();

  // Create PostRequestInfo and call client.Post() directly
  PostRequestInfo post_info(url, header_map, http_params,
                            const_data_ptr_cast(buffer_in), buffer_in_len);
  fprintf(stderr, "[StorageBox] CustomRequest: About to call client->Post()\n");
  fflush(stderr);
  auto result = client->Post(post_info);
  fprintf(stderr, "[StorageBox] CustomRequest: Post() completed\n");
  fflush(stderr);

  // Copy the result body
  if (result) {
    result->body = std::move(post_info.buffer_out);
  }

  // Restore headers
  http_params.extra_headers = original_extra_headers;

  return result;
}

string StorageBoxFileSystem::DirectPropfindRequest(
    const string &url, const StorageBoxAuthParams &auth_params, int depth) {
  // We need a file handle to make HTTP requests through the proper
  // infrastructure Since we're being called from Glob which has an opener, we
  // should create a temporary handle For now, we'll return empty and the caller
  // should handle creating the handle properly
  return "";
}

void StorageBoxFileSystem::AddAuthHeaders(
    HTTPHeaders &headers, const StorageBoxAuthParams &auth_params) {
  if (!auth_params.username.empty() || !auth_params.password.empty()) {
    string credentials = auth_params.username + ":" + auth_params.password;
    string encoded = Base64Encode(credentials);
    headers["Authorization"] = "Basic " + encoded;
    fprintf(
        stderr,
        "[StorageBox] AddAuthHeaders: Added Authorization header for user %s\n",
        auth_params.username.c_str());
  } else {
    fprintf(stderr,
            "[StorageBox] AddAuthHeaders: NO auth credentials available!\n");
  }
}

string StorageBoxFileSystem::GetName() const { return "StorageBoxFileSystem"; }

bool StorageBoxFileSystem::IsStorageBoxUrl(const string &url) {
  // Check for storagebox:// protocol (Hetzner Storage Box shorthand)
  if (StringUtil::StartsWith(url, "storagebox://")) {
    return true;
  }
  // Check for Hetzner Storage Box URLs
  if (url.find(".your-storagebox.de/") != string::npos) {
    return true;
  }
  return false;
}

bool StorageBoxFileSystem::CanHandleFile(const string &fpath) {
  return IsStorageBoxUrl(fpath);
}

duckdb::unique_ptr<HTTPFileHandle>
StorageBoxFileSystem::CreateHandle(const OpenFileInfo &file,
                                   FileOpenFlags flags,
                                   optional_ptr<FileOpener> opener) {
  D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

  static int call_count = 0;
  call_count++;
  fprintf(stderr,
          "[StorageBox] CreateHandle #%d called for: %s, flags: read=%d "
          "write=%d create=%d overwrite=%d\n",
          call_count, file.path.c_str(), flags.OpenForReading(),
          flags.OpenForWriting(), flags.CreateFileIfNotExists(),
          flags.OverwriteExistingFile());

  // First, read auth params using ORIGINAL URL for secret matching
  // This is critical for proper secret scoping - secrets are scoped to
  // storagebox:// URLs, not the converted https:// URLs
  FileOpenerInfo info;
  info.file_path =
      file.path; // Use ORIGINAL URL (e.g., storagebox://u507042/file.parquet)
  auto auth_params = StorageBoxAuthParams::ReadFrom(opener, info);

  // Parse and convert the URL for actual HTTP operations (e.g., storagebox://
  // -> https://)
  auto parsed_url = ParseUrl(file.path);
  string converted_url = parsed_url.GetHTTPUrl();

  // Create a modified file info with the converted URL for HTTP operations
  OpenFileInfo converted_file = file;
  converted_file.path = converted_url;

  // Use built-in HTTP utility (only using standard HTTP verbs: GET, PUT,
  // DELETE, HEAD)
  auto http_util = HTTPFSUtil::GetHTTPUtil(opener);
  fprintf(stderr, "[StorageBox] CreateHandle: Using http_util: %s\n",
          http_util->GetName().c_str());
  fflush(stderr);

  auto params = http_util->InitializeParameters(opener, &info);
  auto http_params_p = dynamic_cast<HTTPFSParams *>(params.get());
  if (!http_params_p) {
    throw InternalException("Failed to cast HTTP params");
  }

  auto handle = make_uniq<StorageBoxFileHandle>(
      *this, converted_file, flags, std::move(params), auth_params, http_util);
  handle->original_url = file.path; // Store original storagebox:// URL
  return handle;
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::PropfindRequest(FileHandle &handle, string url,
                                      HTTPHeaders header_map, int depth) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);
  header_map["Depth"] = to_string(depth);
  header_map["Content-Type"] = "application/xml; charset=utf-8";

  // Basic PROPFIND request body
  string propfind_body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                         "<D:propfind xmlns:D=\"DAV:\">"
                         "<D:prop>"
                         "<D:resourcetype/>"
                         "<D:getcontentlength/>"
                         "<D:getlastmodified/>"
                         "</D:prop>"
                         "</D:propfind>";

  // Use CustomRequest which sets up PROPFIND properly
  return CustomRequest(handle, url, header_map, "PROPFIND",
                       const_cast<char *>(propfind_body.c_str()),
                       propfind_body.size());
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::MkcolRequest(FileHandle &handle, string url,
                                   HTTPHeaders header_map) {
  fprintf(stderr, "[StorageBox] MkcolRequest called for URL: %s\n",
          url.c_str());

  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);

  fprintf(stderr, "[StorageBox] MkcolRequest: Sending MKCOL request\n");

  // Use MKCOL to create directory (proper WebDAV method)
  auto response = CustomRequest(handle, url, header_map, "MKCOL", nullptr, 0);

  fprintf(stderr, "[StorageBox] MkcolRequest: Got response %d\n",
          static_cast<int>(response->status));
  return response;
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::MoveRequest(FileHandle &handle, string source_url,
                                  string dest_url, HTTPHeaders header_map) {
  fprintf(stderr, "[StorageBox] MoveRequest called: %s -> %s\n",
          source_url.c_str(), dest_url.c_str());

  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);

  // Add required WebDAV MOVE headers (RFC 4918 Section 9.9)
  header_map["Destination"] = dest_url;
  header_map["Overwrite"] = "T"; // Allow overwriting destination if it exists

  fprintf(stderr, "[StorageBox] MoveRequest: Sending MOVE request\n");

  // Use MOVE to rename/move the file (server-side operation)
  auto response =
      CustomRequest(handle, source_url, header_map, "MOVE", nullptr, 0);

  fprintf(stderr, "[StorageBox] MoveRequest: Got response %d\n",
          static_cast<int>(response->status));
  return response;
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::HeadRequest(FileHandle &handle, string url,
                                  HTTPHeaders header_map) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);
  return HTTPFileSystem::HeadRequest(handle, url, header_map);
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::GetRequest(FileHandle &handle, string url,
                                 HTTPHeaders header_map) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);
  return HTTPFileSystem::GetRequest(handle, url, header_map);
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::GetRangeRequest(FileHandle &handle, string url,
                                      HTTPHeaders header_map, idx_t file_offset,
                                      char *buffer_out, idx_t buffer_out_len) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);
  return HTTPFileSystem::GetRangeRequest(handle, url, header_map, file_offset,
                                         buffer_out, buffer_out_len);
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::PutRequest(FileHandle &handle, string url,
                                 HTTPHeaders header_map, char *buffer_in,
                                 idx_t buffer_in_len, string params) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);
  return HTTPFileSystem::PutRequest(handle, url, header_map, buffer_in,
                                    buffer_in_len, params);
}

duckdb::unique_ptr<HTTPResponse> StorageBoxFileSystem::PutRequestFromFile(
    FileHandle &handle, string url, HTTPHeaders header_map,
    const string &file_path, idx_t file_size) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);

  fprintf(stderr,
          "[StorageBox] PutRequestFromFile: Uploading from %s (%llu bytes)\n",
          file_path.c_str(), (unsigned long long)file_size);

  // Open the file for reading
  FILE *fp = fopen(file_path.c_str(), "rb");
  if (!fp) {
    throw IOException("Failed to open temp file %s for streaming upload",
                      file_path);
  }

  // Get the HTTP client and set up file streaming
  auto &http_util = wfh.http_params.http_util;
  auto client = wfh.GetClient();
  SetHTTPClientUploadFile(client.get(), fp, file_size);

  // Create the PUT request
  string content_type = "application/octet-stream";
  PutRequestInfo put_request(url, header_map, wfh.http_params, nullptr,
                             file_size, content_type);

  // Make the request with our configured client
  auto response = http_util.Request(put_request, client);

  // Store client back for reuse
  wfh.StoreClient(std::move(client));

  // Close the file after upload
  fclose(fp);

  return response;
}

duckdb::unique_ptr<HTTPResponse>
StorageBoxFileSystem::DeleteRequest(FileHandle &handle, string url,
                                    HTTPHeaders header_map) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  AddAuthHeaders(header_map, wfh.auth_params);
  return HTTPFileSystem::DeleteRequest(handle, url, header_map);
}

void StorageBoxFileSystem::RemoveFile(const string &filename,
                                      optional_ptr<FileOpener> opener) {
  auto parsed_url = ParseUrl(filename);
  string http_url = parsed_url.GetHTTPUrl();

  FileOpenerInfo info;
  info.file_path = filename;
  auto auth_params = StorageBoxAuthParams::ReadFrom(opener, info);

  // Create a temporary handle for the delete operation
  OpenFileInfo file_info;
  file_info.path = filename;
  auto handle = CreateHandle(file_info, FileOpenFlags::FILE_FLAGS_READ, opener);
  handle->Initialize(opener);

  HTTPHeaders headers;
  auto response = DeleteRequest(*handle, http_url, headers);

  if (response->status != HTTPStatusCode::OK_200 &&
      response->status != HTTPStatusCode::NoContent_204 &&
      response->status != HTTPStatusCode::Accepted_202) {
    throw IOException("Failed to delete file %s: HTTP %d", filename,
                      static_cast<int>(response->status));
  }
}

void StorageBoxFileSystem::MoveFile(const string &source, const string &target,
                                    optional_ptr<FileOpener> opener) {
  fprintf(stderr, "[StorageBox] MoveFile called: %s -> %s\n", source.c_str(),
          target.c_str());

  // Use SSH mv -f command for server-side move with forced overwrite
  // This is more efficient than download + upload, especially for large files
  try {
    auto ssh_client = GetOrCreateSSHClient(source, opener);
    auto source_params = ParseSSHParams(source, opener);
    auto target_params = ParseSSHParams(target, opener);

    // Use SSH mv -f command to force overwrite if destination exists
    string mv_cmd =
        "mv -f " + source_params.remote_path + " " + target_params.remote_path;
    fprintf(stderr, "[StorageBox SSH] Executing: %s\n", mv_cmd.c_str());

    ssh_client->ExecuteCommand(mv_cmd);

    fprintf(stderr, "[StorageBox] MoveFile: Successfully moved file via SSH\n");
  } catch (const std::exception &e) {
    fprintf(stderr, "[StorageBox] MoveFile: FAILED via SSH: %s\n", e.what());
    throw IOException("Failed to move file %s to %s via SSH: %s", source,
                      target, e.what());
  }
}

void StorageBoxFileSystem::CreateDirectory(const string &directory,
                                           optional_ptr<FileOpener> opener) {
  fprintf(stderr, "[StorageBox] CreateDirectory called for: %s\n",
          directory.c_str());

  // Use SSH mkdir -p for directory creation (more efficient than WebDAV MKCOL)
  try {
    auto ssh_client = GetOrCreateSSHClient(directory, opener);
    auto params = ParseSSHParams(directory, opener);

    // Use mkdir -p to create directory and all parent directories
    string command = "mkdir -p " + params.remote_path;
    fprintf(stderr, "[StorageBox SSH] Executing: %s\n", command.c_str());

    ssh_client->ExecuteCommand(command);

    fprintf(stderr, "[StorageBox] CreateDirectory: SUCCESS (via SSH)\n");
    return;
  } catch (const std::exception &e) {
    fprintf(stderr, "[StorageBox] CreateDirectory: FAILED via SSH: %s\n",
            e.what());
    throw IOException("Failed to create directory %s via SSH: %s", directory,
                      e.what());
  }
}

void StorageBoxFileSystem::CreateDirectoryRecursive(
    const string &directory, optional_ptr<FileOpener> opener) {
  // Use standard CreateDirectory which requires an opener
  FileOpenerInfo info;
  info.file_path = directory;
  auto auth_params = StorageBoxAuthParams::ReadFrom(opener, info);

  // Parse URL to extract path components
  auto parsed_url = ParseUrl(directory);
  string path = parsed_url.path;

  // Split path into components
  vector<string> path_parts;
  string current;
  for (char c : path) {
    if (c == '/') {
      if (!current.empty()) {
        path_parts.push_back(current);
        current.clear();
      }
    } else {
      current += c;
    }
  }
  if (!current.empty()) {
    path_parts.push_back(current);
  }

  // Build up directory path incrementally
  string accumulated_path;
  string protocol_prefix;
  if (StringUtil::StartsWith(directory, "storagebox://")) {
    // Extract username from storagebox URL
    string remainder = directory.substr(13);
    auto slash_pos = remainder.find('/');
    string username = remainder.substr(0, slash_pos);
    protocol_prefix = "storagebox://" + username;
  } else {
    protocol_prefix = parsed_url.http_proto + "://" + parsed_url.host;
  }

  // Create each directory level
  for (const auto &part : path_parts) {
    accumulated_path += "/" + part;
    string full_path = protocol_prefix + accumulated_path;

    // Try to create this directory level
    try {
      CreateDirectory(full_path, opener);
    } catch (const IOException &e) {
      // Re-throw critical errors like insufficient storage
      string error_msg = e.what();
      if (error_msg.find("Storage is full") != string::npos ||
          error_msg.find("insufficient storage") != string::npos) {
        throw;
      }
      // Ignore other errors - directory might already exist
      // We'll let the final write operation fail if there's a real issue
    }
  }
}

void StorageBoxFileSystem::CreateDirectoryWithHandle(
    const string &directory, StorageBoxFileHandle &handle) {
  fprintf(stderr, "[StorageBox] CreateDirectoryWithHandle called for: %s\n",
          directory.c_str());

  // If directory is already an HTTP URL, use it directly
  string http_url;
  if (StringUtil::StartsWith(directory, "http://") ||
      StringUtil::StartsWith(directory, "https://")) {
    http_url = directory;
  } else {
    auto parsed_url = ParseUrl(directory);
    http_url = parsed_url.GetHTTPUrl();
  }

  // Ensure the URL ends with a slash for directory creation
  if (!StringUtil::EndsWith(http_url, "/")) {
    http_url += "/";
  }

  fprintf(stderr,
          "[StorageBox] CreateDirectoryWithHandle: Sending MKCOL to %s\n",
          http_url.c_str());

  HTTPHeaders headers;
  auto response = MkcolRequest(handle, http_url, headers);

  fprintf(stderr, "[StorageBox] CreateDirectoryWithHandle: MKCOL returned %d\n",
          static_cast<int>(response->status));

  if (response->status != HTTPStatusCode::Created_201 &&
      response->status != HTTPStatusCode::OK_200 &&
      response->status != HTTPStatusCode::NoContent_204) {
    // Directory might already exist (405 Method Not Allowed)
    if (response->status == HTTPStatusCode::MethodNotAllowed_405) {
      return; // Directory already exists, success
    }

    // If MKCOL not supported, return (directory might not exist on this server)
    if (response->status == HTTPStatusCode::NotFound_404) {
      // Don't throw error - let the file write fail if directory truly doesn't
      // exist
      return;
    }

    // Check for insufficient storage (507)
    if (response->status == HTTPStatusCode::InsufficientStorage_507) {
      fprintf(
          stderr,
          "[StorageBox] CreateDirectoryWithHandle: Storage is full (507)\n");
      throw IOException("Failed to create directory %s: Storage is full. The "
                        "StorageBox server has "
                        "insufficient storage space available. Free up space "
                        "or resize your storage.",
                        directory);
    }

    throw IOException("Failed to create directory %s: HTTP %d", directory,
                      static_cast<int>(response->status));
  }
}

void StorageBoxFileSystem::CreateDirectoryRecursiveWithHandle(
    const string &directory, StorageBoxFileHandle &handle) {
  fprintf(stderr,
          "[StorageBox] CreateDirectoryRecursiveWithHandle called for: %s\n",
          directory.c_str());

  // Check if this is already an HTTP(S) URL - if so, we need to reconstruct the
  // original format
  string directory_to_use = directory;
  if (StringUtil::StartsWith(directory, "http://") ||
      StringUtil::StartsWith(directory, "https://")) {
    // This is an HTTP URL - need to reconstruct original format
    // For now, just extract the path component and use it with
    // CreateDirectoryWithHandle which works with the handle we already have
    fprintf(stderr, "[StorageBox] CreateDirectoryRecursiveWithHandle: Got HTTP "
                    "URL, will use CreateDirectoryWithHandle directly\n");

    // Just call CreateDirectoryWithHandle directly since we already have a
    // handle
    CreateDirectoryWithHandle(directory_to_use, handle);
    return;
  }

  // Parse URL to extract path components
  auto parsed_url = ParseUrl(directory_to_use);
  string path = parsed_url.path;

  // Split path into components
  vector<string> path_parts;
  string current;
  for (char c : path) {
    if (c == '/') {
      if (!current.empty()) {
        path_parts.push_back(current);
        current.clear();
      }
    } else {
      current += c;
    }
  }
  if (!current.empty()) {
    path_parts.push_back(current);
  }

  // Build up directory path incrementally
  string accumulated_path;
  string protocol_prefix;
  if (StringUtil::StartsWith(directory, "storagebox://")) {
    // Extract username from storagebox URL
    string remainder = directory.substr(13);
    auto slash_pos = remainder.find('/');
    string username = remainder.substr(0, slash_pos);
    protocol_prefix = "storagebox://" + username;
  } else {
    protocol_prefix = parsed_url.http_proto + "://" + parsed_url.host;
  }

  // Create each directory level
  for (const auto &part : path_parts) {
    accumulated_path += "/" + part;
    string full_path = protocol_prefix + accumulated_path;

    // Try to create this directory level
    try {
      CreateDirectoryWithHandle(full_path, handle);
    } catch (const IOException &e) {
      // Ignore errors - directory might already exist
      // We'll let the final write operation fail if there's a real issue
    }
  }
}

void StorageBoxFileSystem::RemoveDirectory(const string &directory,
                                           optional_ptr<FileOpener> opener) {
  RemoveFile(directory, opener);
}

bool StorageBoxFileSystem::FileExists(const string &filename,
                                      optional_ptr<FileOpener> opener) {
  fprintf(stderr, "[StorageBox] FileExists called for: %s\n", filename.c_str());

  // First check if it exists at all using the parent implementation
  try {
    if (!HTTPFileSystem::FileExists(filename, opener)) {
      fprintf(stderr, "[StorageBox] FileExists: parent returned false\n");
      return false;
    }
    fprintf(stderr, "[StorageBox] FileExists: parent returned true\n");
  } catch (const HTTPException &e) {
    // File doesn't exist or is inaccessible
    fprintf(stderr, "[StorageBox] FileExists: parent threw HTTPException: %s\n",
            e.what());
    return false;
  }

  // Now check if it's actually a directory
  // WebDAV directories need a trailing slash, so we check both ways
  try {
    if (DirectoryExists(filename, opener)) {
      // It's a directory, not a file
      fprintf(stderr, "[StorageBox] FileExists: DirectoryExists returned true, "
                      "so NOT a file\n");
      return false;
    }
    fprintf(stderr,
            "[StorageBox] FileExists: DirectoryExists returned false\n");
  } catch (const HTTPException &e) {
    // Ignore directory check errors - if we can't check, assume it's not a
    // directory
    fprintf(stderr,
            "[StorageBox] FileExists: DirectoryExists threw HTTPException\n");
  }

  // It exists and is not a directory, so it must be a file
  fprintf(stderr, "[StorageBox] FileExists: Returning true (is a file)\n");
  return true;
}

bool StorageBoxFileSystem::DirectoryExists(const string &directory,
                                           optional_ptr<FileOpener> opener) {
  fprintf(stderr, "[StorageBox] DirectoryExists called for: %s\n",
          directory.c_str());

  auto parsed_url = ParseUrl(directory);
  string http_url = parsed_url.GetHTTPUrl();

  if (!StringUtil::EndsWith(http_url, "/")) {
    http_url += "/";
  }

  FileOpenerInfo info;
  info.file_path = directory;

  // Create a temporary handle for the HEAD operation
  OpenFileInfo file_info;
  file_info.path = directory;
  auto handle = CreateHandle(file_info, FileOpenFlags::FILE_FLAGS_READ, opener);

  // Try to initialize the handle - if it fails, the directory doesn't exist
  try {
    fprintf(stderr,
            "[StorageBox] DirectoryExists: About to initialize handle\n");
    handle->Initialize(opener);
    fprintf(stderr, "[StorageBox] DirectoryExists: Initialize succeeded\n");
  } catch (const HTTPException &e) {
    // Directory doesn't exist or is inaccessible
    fprintf(
        stderr,
        "[StorageBox] DirectoryExists: Initialize threw HTTPException: %s\n",
        e.what());
    return false;
  } catch (const std::exception &e) {
    fprintf(
        stderr,
        "[StorageBox] DirectoryExists: Initialize threw std::exception: %s\n",
        e.what());
    return false;
  }

  // Try the HEAD request to check if the directory exists
  try {
    fprintf(stderr,
            "[StorageBox] DirectoryExists: About to send HEAD request\n");
    HTTPHeaders headers;
    auto response = HeadRequest(*handle, http_url, headers);
    bool exists = response->status == HTTPStatusCode::OK_200 ||
                  response->status == HTTPStatusCode::NoContent_204;
    fprintf(stderr,
            "[StorageBox] DirectoryExists: HEAD returned %d, exists=%d\n",
            static_cast<int>(response->status), exists);
    return exists;
  } catch (const HTTPException &e) {
    // Directory doesn't exist or is inaccessible
    fprintf(stderr,
            "[StorageBox] DirectoryExists: HEAD threw HTTPException: %s\n",
            e.what());
    return false;
  } catch (const std::exception &e) {
    fprintf(stderr,
            "[StorageBox] DirectoryExists: HEAD threw std::exception: %s\n",
            e.what());
    return false;
  }
}

void StorageBoxFileSystem::Write(FileHandle &handle, void *buffer,
                                 int64_t nr_bytes, idx_t location) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();

  fprintf(stderr,
          "[StorageBox] Write called for: %s, bytes: %lld, location: %llu, "
          "current_offset: %llu\n",
          wfh.path.c_str(), nr_bytes, (unsigned long long)location,
          (unsigned long long)wfh.file_offset);

  // Validate that the write location matches our buffer position
  idx_t expected_location = wfh.total_bytes_uploaded + wfh.write_buffer.size();
  if (location != expected_location) {
    throw IOException("StorageBox does not support non-sequential writes. "
                      "Expected location %llu but got %llu",
                      (unsigned long long)expected_location,
                      (unsigned long long)location);
  }

  const char *data = static_cast<const char *>(buffer);
  idx_t bytes_remaining = nr_bytes;
  idx_t offset = 0;

  // Stream data in chunks, flushing when buffer reaches CHUNK_SIZE
  while (bytes_remaining > 0) {
    // Calculate how much we can add to current buffer before hitting chunk size
    idx_t space_in_buffer =
        StorageBoxFileHandle::CHUNK_SIZE - wfh.write_buffer.size();
    idx_t bytes_to_buffer = std::min(bytes_remaining, space_in_buffer);

    // Add data to buffer
    wfh.write_buffer.append(data + offset, bytes_to_buffer);
    wfh.buffer_dirty = true;
    offset += bytes_to_buffer;
    bytes_remaining -= bytes_to_buffer;

    // Flush if buffer is full
    if (wfh.write_buffer.size() >= StorageBoxFileHandle::CHUNK_SIZE) {
      wfh.FlushBuffer();
    }
  }

  wfh.file_offset += nr_bytes;

  fprintf(stderr,
          "[StorageBox] Write: buffered %lld bytes, total uploaded: %zu, "
          "buffer: %zu\n",
          nr_bytes, wfh.total_bytes_uploaded, wfh.write_buffer.size());
}

void StorageBoxFileSystem::FileSync(FileHandle &handle) {
  auto &wfh = handle.Cast<StorageBoxFileHandle>();
  fprintf(stderr, "[StorageBox] FileSync called for: %s\n", wfh.path.c_str());
  wfh.FlushBuffer();
}

// Helper function to parse XML and extract file paths from PROPFIND response
static vector<OpenFileInfo> ParsePropfindResponse(const string &xml_response,
                                                  const string &base_path) {
  vector<OpenFileInfo> result;

  // Simple XML parsing - look for <D:href> or <href> tags
  // WebDAV PROPFIND responses contain <response> elements with <href> child
  // elements
  size_t pos = 0;
  while ((pos = xml_response.find("<D:href>", pos)) != string::npos ||
         (pos = xml_response.find("<href>", pos)) != string::npos) {

    string tag_open =
        xml_response.substr(pos, 8) == "<D:href>" ? "<D:href>" : "<href>";
    string tag_close = tag_open == "<D:href>" ? "</D:href>" : "</href>";

    size_t start = pos + tag_open.length();
    size_t end = xml_response.find(tag_close, start);

    if (end == string::npos) {
      break;
    }

    string href = xml_response.substr(start, end - start);

    // URL decode the href
    string decoded_href;
    for (size_t i = 0; i < href.length(); i++) {
      if (href[i] == '%' && i + 2 < href.length()) {
        string hex = href.substr(i + 1, 2);
        char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
        decoded_href += ch;
        i += 2;
      } else {
        decoded_href += href[i];
      }
    }

    // Skip the directory itself (entries ending with /)
    if (!StringUtil::EndsWith(decoded_href, "/")) {
      // Extract just the path portion (remove any host/port prefix)
      // WebDAV servers often return absolute paths like /path/to/file
      OpenFileInfo info;
      info.path = decoded_href;
      result.push_back(info);
    }

    pos = end + tag_close.length();
  }

  return result;
}

// Pattern matching helper (similar to S3)
static bool Match(vector<string>::const_iterator key,
                  vector<string>::const_iterator key_end,
                  vector<string>::const_iterator pattern,
                  vector<string>::const_iterator pattern_end) {

  while (key != key_end && pattern != pattern_end) {
    if (*pattern == "**") {
      if (std::next(pattern) == pattern_end) {
        return true;
      }
      while (key != key_end) {
        if (Match(key, key_end, std::next(pattern), pattern_end)) {
          return true;
        }
        key++;
      }
      return false;
    }
    if (!Glob(key->data(), key->length(), pattern->data(), pattern->length())) {
      return false;
    }
    key++;
    pattern++;
  }
  return key == key_end && pattern == pattern_end;
}

vector<OpenFileInfo> StorageBoxFileSystem::Glob(const string &glob_pattern,
                                                FileOpener *opener) {
  fprintf(stderr, "[StorageBox] Glob called for pattern: %s\n",
          glob_pattern.c_str());

  if (!opener) {
    // Without an opener, we can't authenticate, so just return the pattern
    fprintf(stderr, "[StorageBox] Glob: no opener, returning pattern as-is\n");
    return {glob_pattern};
  }

  // Parse the StorageBox URL
  auto parsed_url = ParseUrl(glob_pattern);
  string path = parsed_url.path;

  // Find the first wildcard character
  auto first_wildcard_pos = path.find_first_of("*[\\");
  if (first_wildcard_pos == string::npos) {
    // No wildcards, return as-is
    return {glob_pattern};
  }

  // Extract the shared prefix path (up to the last '/' before the wildcard)
  auto last_slash_before_wildcard = path.rfind('/', first_wildcard_pos);
  string prefix_path;
  if (last_slash_before_wildcard != string::npos) {
    prefix_path = path.substr(0, last_slash_before_wildcard + 1);
  } else {
    prefix_path = "/";
  }

  // Construct the base URL for SSH listing
  // Extract the username from the storagebox:// pattern
  string remainder = glob_pattern.substr(13); // Skip "storagebox://"
  auto slash_pos = remainder.find('/');
  string username = remainder.substr(0, slash_pos);
  string non_wildcard_path = "storagebox://" + username + prefix_path;

  // Use SSH tree command for recursive listing (much faster than WebDAV
  // PROPFIND)
  vector<string> file_paths;
  try {
    file_paths = ListFilesViaSSH(non_wildcard_path, opener);
  } catch (const std::exception &e) {
    fprintf(stderr, "[StorageBox] Glob: SSH tree listing failed: %s\n",
            e.what());
    return {};
  }

  if (file_paths.empty()) {
    fprintf(stderr, "[StorageBox] Glob: No files found via SSH tree\n");
    return {};
  }

  // Match the pattern against the file paths
  vector<string> pattern_splits = StringUtil::Split(path, "/");
  vector<OpenFileInfo> result;

  // username is already defined earlier in the function

  for (const auto &file_path : file_paths) {
    // The file_path from tree is relative to the remote_path
    // We need to construct the full path including prefix_path
    string full_path = prefix_path + file_path;

    // Normalize path (remove leading ./ if present from tree -f output)
    if (StringUtil::StartsWith(full_path, "./")) {
      full_path = full_path.substr(2);
    }
    // Ensure leading slash
    if (!StringUtil::StartsWith(full_path, "/")) {
      full_path = "/" + full_path;
    }

    vector<string> key_splits = StringUtil::Split(full_path, "/");
    bool is_match = Match(key_splits.begin(), key_splits.end(),
                          pattern_splits.begin(), pattern_splits.end());

    if (is_match) {
      // Reconstruct the full storagebox:// URL
      string full_url = "storagebox://" + username + full_path;

      OpenFileInfo info;
      info.path = full_url;
      result.push_back(info);
    }
  }

  fprintf(stderr, "[StorageBox] Glob: Matched %zu files from %zu total\n",
          result.size(), file_paths.size());
  return result;
}

unique_ptr<FileHandle>
StorageBoxFileSystem::OpenFileExtended(const OpenFileInfo &file,
                                       FileOpenFlags flags,
                                       optional_ptr<FileOpener> opener) {
  fprintf(stderr,
          "[StorageBox] OpenFileExtended called for: %s, flags: read=%d "
          "write=%d create=%d overwrite=%d\n",
          file.path.c_str(), flags.OpenForReading(), flags.OpenForWriting(),
          flags.CreateFileIfNotExists(), flags.OverwriteExistingFile());

  // Try to open the file using the parent implementation
  try {
    return HTTPFileSystem::OpenFileExtended(file, flags, opener);
  } catch (const HTTPException &e) {
    fprintf(stderr, "[StorageBox] OpenFileExtended: caught HTTPException: %s\n",
            e.what());

    // If we're opening for reading and got a 404, return nullptr to indicate
    // file doesn't exist This allows ducklake and other extensions to handle
    // missing files gracefully
    if (flags.OpenForReading() && !flags.OpenForWriting()) {
      fprintf(stderr, "[StorageBox] OpenFileExtended: opening for read-only, "
                      "returning nullptr for missing file\n");
      return nullptr;
    }

    // For other cases, re-throw the exception
    fprintf(stderr, "[StorageBox] OpenFileExtended: re-throwing exception\n");
    throw;
  }
}

bool StorageBoxFileSystem::ListFiles(
    const string &directory,
    const std::function<void(const string &, bool)> &callback,
    FileOpener *opener) {
  fprintf(stderr, "[StorageBox] ListFiles called for: %s\n", directory.c_str());

  string trimmed_dir = directory;
  // Remove trailing slash if present
  if (StringUtil::EndsWith(trimmed_dir, "/")) {
    trimmed_dir = trimmed_dir.substr(0, trimmed_dir.length() - 1);
  }

  fprintf(stderr, "[StorageBox] ListFiles: About to glob with pattern: %s/**\n",
          trimmed_dir.c_str());

  // Use Glob with ** pattern to list all files recursively
  auto glob_res = Glob(trimmed_dir + "/**", opener);

  fprintf(stderr, "[StorageBox] ListFiles: Glob returned %zu results\n",
          glob_res.size());

  if (glob_res.empty()) {
    return false;
  }

  for (const auto &file : glob_res) {
    callback(file.path, false);
  }

  return true;
}

HTTPException StorageBoxFileSystem::GetHTTPError(FileHandle &,
                                                 const HTTPResponse &response,
                                                 const string &url) {
  auto status_message = HTTPUtil::GetStatusMessage(response.status);
  string error = "StorageBox error on '" + url + "' (HTTP " +
                 to_string(static_cast<int>(response.status)) + " " +
                 status_message + ")";
  return HTTPException(response, error);
}

} // namespace duckdb
