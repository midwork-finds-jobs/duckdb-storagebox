#include "storagebox_secrets.hpp"
#include "duckdb/main/secret/secret.hpp"
#include <duckdb/common/string_util.hpp>

namespace duckdb {

void CreateStorageBoxSecretFunctions::Register(ExtensionLoader &loader) {
  // StorageBox secret
  SecretType secret_type_storagebox;
  secret_type_storagebox.name = STORAGEBOX_TYPE;
  secret_type_storagebox.deserializer =
      KeyValueSecret::Deserialize<KeyValueSecret>;
  secret_type_storagebox.default_provider = "config";
  secret_type_storagebox.extension = "storagebox";
  loader.RegisterSecretType(secret_type_storagebox);

  // StorageBox config provider
  CreateSecretFunction storagebox_config_fun = {
      STORAGEBOX_TYPE, "config", CreateStorageBoxSecretFromConfig};
  storagebox_config_fun.named_parameters["username"] = LogicalType::VARCHAR;
  storagebox_config_fun.named_parameters["password"] = LogicalType::VARCHAR;
  loader.RegisterFunction(storagebox_config_fun);
}

unique_ptr<BaseSecret>
CreateStorageBoxSecretFunctions::CreateSecretFunctionInternal(
    ClientContext &context, CreateSecretInput &input) {
  // Set scope to user provided scope or the default
  auto scope = input.scope;
  if (scope.empty()) {
    // Default scope includes storagebox:// and HTTPS URLs
    scope.push_back("storagebox://");
    scope.push_back("https://");
  }
  auto return_value =
      make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

  //! Set key value map
  for (const auto &named_param : input.options) {
    auto lower_name = StringUtil::Lower(named_param.first);
    if (lower_name == "username") {
      return_value->secret_map["username"] = named_param.second.ToString();
    } else if (lower_name == "password") {
      return_value->secret_map["password"] = named_param.second.ToString();
    }
  }

  //! Set redact keys
  return_value->redact_keys = {"password"};

  return std::move(return_value);
}

unique_ptr<BaseSecret>
CreateStorageBoxSecretFunctions::CreateStorageBoxSecretFromConfig(
    ClientContext &context, CreateSecretInput &input) {
  return CreateSecretFunctionInternal(context, input);
}

} // namespace duckdb
