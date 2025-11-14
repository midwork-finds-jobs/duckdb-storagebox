#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/file_opener.hpp"
#include "httpfs.hpp"
#include "ssh_client.hpp"
#include <future>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace duckdb {

struct StorageBoxAuthParams {
  string username;
  string password;

  static StorageBoxAuthParams ReadFrom(optional_ptr<FileOpener> opener,
                                       FileOpenerInfo &info);
};

struct ParsedStorageBoxUrl {
  string http_proto;
  string host;
  string path;

  string GetHTTPUrl() const;
};

class StorageBoxFileHandle : public HTTPFileHandle {
  friend class StorageBoxFileSystem;

public:
  StorageBoxFileHandle(FileSystem &fs, const OpenFileInfo &file,
                       FileOpenFlags flags,
                       unique_ptr<HTTPParams> http_params_p,
                       const StorageBoxAuthParams &auth_params_p,
                       shared_ptr<HTTPUtil> http_util_p = nullptr)
      : HTTPFileHandle(fs, file, flags, std::move(http_params_p)),
        auth_params(auth_params_p), http_util(http_util_p) {
    if (flags.OpenForReading() && flags.OpenForWriting()) {
      throw NotImplementedException(
          "Cannot open a StorageBox file for both reading and writing");
    } else if (flags.OpenForAppending()) {
      throw NotImplementedException(
          "Cannot open a StorageBox file for appending");
    }
  }
  ~StorageBoxFileHandle() override;

  StorageBoxAuthParams auth_params;
  // Store HTTPUtil to ensure it lives as long as the handle
  shared_ptr<HTTPUtil> http_util;
  // Store file opener for SSH operations
  optional_ptr<FileOpener> file_opener = nullptr;
  // Store original storagebox:// URL for SSH operations
  string original_url;
  // Write buffer for accumulating writes before flushing to StorageBox
  string write_buffer;
  bool buffer_dirty = false;

  // Multi-part streaming upload using SFTP append
  static constexpr idx_t CHUNK_SIZE =
      10 * 1024 * 1024;            // 10MB chunks for streaming
  size_t chunk_count = 0;          // Number of chunks uploaded
  size_t total_bytes_uploaded = 0; // Total bytes uploaded so far

  // Async upload tracking
  std::vector<std::future<void>>
      pending_uploads;     // Track async upload operations
  std::mutex upload_mutex; // Protect chunk_count and pending_uploads

  // Progressive chunk combining
  std::vector<bool> chunks_uploaded; // Track which chunks have been uploaded
  size_t next_chunk_to_combine = 0;  // Next chunk index that should be combined
  std::mutex combine_mutex;          // Protect combining operations

public:
  void Close() override;
  void Initialize(optional_ptr<FileOpener> opener) override;
  void FlushBuffer();
  void WaitForPendingUploads();
  void
  TryCombineReadyChunks(); // Combine chunks as soon as they're ready in order

protected:
  unique_ptr<HTTPClient> CreateClient() override;
};

class StorageBoxFileSystem : public HTTPFileSystem {
public:
  StorageBoxFileSystem() = default;

  string GetName() const override;

public:
  // StorageBox/WebDAV-specific methods
  duckdb::unique_ptr<HTTPResponse> PropfindRequest(FileHandle &handle,
                                                   string url,
                                                   HTTPHeaders header_map,
                                                   int depth = 1);
  duckdb::unique_ptr<HTTPResponse> MkcolRequest(FileHandle &handle, string url,
                                                HTTPHeaders header_map);
  duckdb::unique_ptr<HTTPResponse> MoveRequest(FileHandle &handle,
                                               string source_url,
                                               string dest_url,
                                               HTTPHeaders header_map);
  duckdb::unique_ptr<HTTPResponse>
  CustomRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                const string &method, char *buffer_in, idx_t buffer_in_len);

  // Override standard methods for StorageBox/WebDAV support
  duckdb::unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, string url,
                                               HTTPHeaders header_map) override;
  duckdb::unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string url,
                                              HTTPHeaders header_map) override;
  duckdb::unique_ptr<HTTPResponse>
  GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                  idx_t file_offset, char *buffer_out,
                  idx_t buffer_out_len) override;
  duckdb::unique_ptr<HTTPResponse>
  PutRequest(FileHandle &handle, string url, HTTPHeaders header_map,
             char *buffer_in, idx_t buffer_in_len, string params = "") override;
  duckdb::unique_ptr<HTTPResponse>
  PutRequestFromFile(FileHandle &handle, string url, HTTPHeaders header_map,
                     const string &file_path, idx_t file_size);
  duckdb::unique_ptr<HTTPResponse>
  DeleteRequest(FileHandle &handle, string url,
                HTTPHeaders header_map) override;

  bool CanHandleFile(const string &fpath) override;
  static bool IsStorageBoxUrl(const string &url);
  void RemoveFile(const string &filename,
                  optional_ptr<FileOpener> opener = nullptr) override;
  void MoveFile(const string &source, const string &target,
                optional_ptr<FileOpener> opener = nullptr) override;
  void CreateDirectory(const string &directory,
                       optional_ptr<FileOpener> opener = nullptr) override;
  void CreateDirectoryRecursive(const string &directory,
                                optional_ptr<FileOpener> opener = nullptr);
  void RemoveDirectory(const string &directory,
                       optional_ptr<FileOpener> opener = nullptr) override;
  void FileSync(FileHandle &handle) override;
  void Write(FileHandle &handle, void *buffer, int64_t nr_bytes,
             idx_t location) override;

  bool OnDiskFile(FileHandle &handle) override { return false; }

  bool FileExists(const string &filename,
                  optional_ptr<FileOpener> opener = nullptr) override;
  bool DirectoryExists(const string &directory,
                       optional_ptr<FileOpener> opener = nullptr) override;
  vector<OpenFileInfo> Glob(const string &glob_pattern,
                            FileOpener *opener = nullptr) override;

  unique_ptr<FileHandle>
  OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
                   optional_ptr<FileOpener> opener) override;
  bool SupportsOpenFileExtended() const override { return true; }

  bool ListFiles(const string &directory,
                 const std::function<void(const string &, bool)> &callback,
                 FileOpener *opener = nullptr) override;

  static ParsedStorageBoxUrl ParseUrl(const string &url);

  // SSH client management for file operations (public for use in FlushBuffer)
  shared_ptr<SSHClient> GetOrCreateSSHClient(const string &url,
                                             optional_ptr<FileOpener> opener);
  SSHConnectionParams ParseSSHParams(const string &url,
                                     optional_ptr<FileOpener> opener);
  vector<string> ListFilesViaSSH(const string &url,
                                 optional_ptr<FileOpener> opener);

protected:
  duckdb::unique_ptr<HTTPFileHandle>
  CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
               optional_ptr<FileOpener> opener) override;

  HTTPException GetHTTPError(FileHandle &, const HTTPResponse &response,
                             const string &url) override;

private:
  void AddAuthHeaders(HTTPHeaders &headers,
                      const StorageBoxAuthParams &auth_params);
  string Base64Encode(const string &input);
  string DirectPropfindRequest(const string &url,
                               const StorageBoxAuthParams &auth_params,
                               int depth);
  void CreateDirectoryWithHandle(const string &directory,
                                 StorageBoxFileHandle &handle);
  void CreateDirectoryRecursiveWithHandle(const string &directory,
                                          StorageBoxFileHandle &handle);

  // SSH client connection pool (one per host)
  std::unordered_map<string, shared_ptr<SSHClient>> ssh_client_pool;
  std::mutex ssh_pool_mutex;
};

} // namespace duckdb
