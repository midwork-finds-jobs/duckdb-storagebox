#pragma once

#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

constexpr const char *STORAGEBOX_TYPE = "storagebox";

struct CreateStorageBoxSecretFunctions {
  static void Register(ExtensionLoader &loader);
  static unique_ptr<BaseSecret>
  CreateStorageBoxSecretFromConfig(ClientContext &context,
                                   CreateSecretInput &input);

private:
  static unique_ptr<BaseSecret>
  CreateSecretFunctionInternal(ClientContext &context,
                               CreateSecretInput &input);
};

} // namespace duckdb
