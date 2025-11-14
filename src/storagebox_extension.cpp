#define DUCKDB_EXTENSION_MAIN

#include "storagebox_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database_manager.hpp"
#include "httpfs_client.hpp"
#include "storagebox_filesystem.hpp"
#include "storagebox_secrets.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
  // Register StorageBox file system
  auto &instance = loader.GetDatabaseInstance();
  auto &config = DBConfig::GetConfig(instance);

  // Set up HTTP utility (CURL-based)
  if (!config.http_util || config.http_util->GetName() != "HTTPFS-Curl") {
    config.http_util = make_shared_ptr<HTTPFSCurlUtil>();
  }

  auto &fs = instance.GetFileSystem();
  fs.RegisterSubSystem(make_uniq<StorageBoxFileSystem>());

  // Register StorageBox secrets
  CreateStorageBoxSecretFunctions::Register(loader);
}

void StorageboxExtension::Load(ExtensionLoader &loader) {
  LoadInternal(loader);
}

std::string StorageboxExtension::Name() { return "storagebox"; }

std::string StorageboxExtension::Version() const {
#ifdef EXT_VERSION_STORAGEBOX
  return EXT_VERSION_STORAGEBOX;
#else
  return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(storagebox, loader) { duckdb::LoadInternal(loader); }
}
