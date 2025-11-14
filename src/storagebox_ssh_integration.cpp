#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "storagebox_filesystem.hpp"
#include <sstream>

namespace duckdb {

// Simple JSON parser for tree command output
struct TreeNode {
  string type; // "file" or "directory"
  string name;
  vector<TreeNode> contents;
};

static void ParseTreeJSON(const string &json, vector<TreeNode> &nodes,
                          size_t &pos);

static void SkipWhitespace(const string &json, size_t &pos) {
  while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\n' ||
                                 json[pos] == '\r' || json[pos] == '\t')) {
    pos++;
  }
}

static string ParseString(const string &json, size_t &pos) {
  // Expect opening quote
  if (pos >= json.length() || json[pos] != '"') {
    throw IOException("Expected '\"' at position %zu", pos);
  }
  pos++;

  string result;
  while (pos < json.length() && json[pos] != '"') {
    if (json[pos] == '\\' && pos + 1 < json.length()) {
      // Handle escaped characters
      pos++;
      switch (json[pos]) {
      case 'n':
        result += '\n';
        break;
      case 't':
        result += '\t';
        break;
      case 'r':
        result += '\r';
        break;
      case '\\':
        result += '\\';
        break;
      case '"':
        result += '"';
        break;
      default:
        result += json[pos];
        break;
      }
    } else {
      result += json[pos];
    }
    pos++;
  }

  if (pos >= json.length()) {
    throw IOException("Unterminated string");
  }
  pos++; // Skip closing quote
  return result;
}

static TreeNode ParseTreeObject(const string &json, size_t &pos) {
  TreeNode node;

  // Expect opening brace
  SkipWhitespace(json, pos);
  if (pos >= json.length() || json[pos] != '{') {
    throw IOException("Expected '{' at position %zu", pos);
  }
  pos++;

  while (true) {
    SkipWhitespace(json, pos);
    if (pos >= json.length())
      break;
    if (json[pos] == '}') {
      pos++;
      break;
    }

    // Skip comma between properties
    if (json[pos] == ',') {
      pos++;
      SkipWhitespace(json, pos);
    }

    // Parse property name
    string key = ParseString(json, pos);

    // Expect colon
    SkipWhitespace(json, pos);
    if (pos >= json.length() || json[pos] != ':') {
      throw IOException("Expected ':' at position %zu", pos);
    }
    pos++;

    SkipWhitespace(json, pos);

    // Parse value based on key
    if (key == "type" || key == "name") {
      string value = ParseString(json, pos);
      if (key == "type") {
        node.type = value;
      } else {
        node.name = value;
      }
    } else if (key == "contents") {
      // Parse array of child nodes
      if (pos >= json.length() || json[pos] != '[') {
        throw IOException("Expected '[' at position %zu", pos);
      }
      pos++;

      ParseTreeJSON(json, node.contents, pos);

      SkipWhitespace(json, pos);
      if (pos >= json.length() || json[pos] != ']') {
        throw IOException("Expected ']' at position %zu", pos);
      }
      pos++;
    } else {
      // Skip unknown property - could be a string, number, etc.
      // For simplicity, skip until next comma or closing brace
      int depth = 0;
      while (pos < json.length()) {
        if (json[pos] == '{' || json[pos] == '[')
          depth++;
        else if (json[pos] == '}' || json[pos] == ']') {
          if (depth == 0)
            break;
          depth--;
        } else if (json[pos] == ',' && depth == 0)
          break;
        else if (json[pos] == '"') {
          pos++;
          while (pos < json.length() && json[pos] != '"') {
            if (json[pos] == '\\')
              pos++;
            pos++;
          }
        }
        pos++;
      }
    }
  }

  return node;
}

static void ParseTreeJSON(const string &json, vector<TreeNode> &nodes,
                          size_t &pos) {
  while (true) {
    SkipWhitespace(json, pos);
    if (pos >= json.length())
      break;
    if (json[pos] == ']')
      break;
    if (json[pos] == ',') {
      pos++;
      continue;
    }

    nodes.push_back(ParseTreeObject(json, pos));
  }
}

static void FlattenTreeNodes(const vector<TreeNode> &nodes,
                             const string &base_path, vector<string> &files) {
  for (const auto &node : nodes) {
    string node_path =
        base_path.empty() ? node.name : base_path + "/" + node.name;

    if (node.type == "file") {
      files.push_back(node_path);
    } else if (node.type == "directory") {
      // Recursively flatten subdirectories
      FlattenTreeNodes(node.contents, node_path, files);
    }
  }
}

SSHConnectionParams
StorageBoxFileSystem::ParseSSHParams(const string &url,
                                     optional_ptr<FileOpener> opener) {
  SSHConnectionParams params;

  // Parse storagebox://username/path or storagebox://hostname/path
  auto parsed = ParseUrl(url);

  // Extract hostname from the URL (e.g., u508112.your-storagebox.de)
  params.hostname = parsed.host;
  params.port = 23; // Hetzner Storage Box uses port 23 for SSH
  params.remote_path = parsed.path;

  // Remove leading slash for relative path
  if (!params.remote_path.empty() && params.remote_path[0] == '/') {
    params.remote_path = params.remote_path.substr(1);
  }

  // Try to get credentials from secrets if opener is provided
  if (opener) {
    FileOpenerInfo info;
    info.file_path = url;
    auto auth_params = StorageBoxAuthParams::ReadFrom(opener, info);

    params.username = auth_params.username;
    params.password = auth_params.password;

    // Check for SSH-specific settings
    try {
      auto secret_manager = FileOpener::TryGetSecretManager(opener);
      if (secret_manager) {
        auto transaction = FileOpener::TryGetCatalogTransaction(opener);
        if (transaction) {
          auto secret_match =
              secret_manager->LookupSecret(*transaction, url, "storagebox");
          if (secret_match.HasMatch()) {
            auto &base_secret = secret_match.GetSecret();
            auto *secret = dynamic_cast<const KeyValueSecret *>(&base_secret);
            if (secret) {
              Value value;
              if (secret->TryGetValue("key_path", value)) {
                params.key_path = value.ToString();
              }
              if (secret->TryGetValue("port", value)) {
                params.port = value.GetValue<int>();
              }
            }
          }
        }
      }
    } catch (...) {
      // Ignore errors getting secret, use what we have
    }
  }

  return params;
}

shared_ptr<SSHClient>
StorageBoxFileSystem::GetOrCreateSSHClient(const string &url,
                                           optional_ptr<FileOpener> opener) {
  auto params = ParseSSHParams(url, opener);

  // Create connection pool key
  string pool_key = params.username + "@" + params.hostname + ":" +
                    std::to_string(params.port);

  std::lock_guard<std::mutex> lock(ssh_pool_mutex);

  // Check if client exists and is still connected
  auto it = ssh_client_pool.find(pool_key);
  if (it != ssh_client_pool.end()) {
    auto &client = it->second;
    if (client && client->ValidateConnection()) {
      fprintf(stderr,
              "[StorageBox SSH] Reusing existing SSH connection for %s\n",
              pool_key.c_str());
      return client;
    } else {
      fprintf(stderr, "[StorageBox SSH] Removing stale SSH connection for %s\n",
              pool_key.c_str());
      ssh_client_pool.erase(it);
    }
  }

  // Create new client
  fprintf(stderr, "[StorageBox SSH] Creating new SSH connection for %s\n",
          pool_key.c_str());
  auto client = make_shared_ptr<SSHClient>(params);
  client->Connect();
  ssh_client_pool[pool_key] = client;

  return client;
}

vector<string>
StorageBoxFileSystem::ListFilesViaSSH(const string &url,
                                      optional_ptr<FileOpener> opener) {
  fprintf(stderr, "[StorageBox SSH] ListFilesViaSSH called for: %s\n",
          url.c_str());

  auto ssh_client = GetOrCreateSSHClient(url, opener);
  auto params = ParseSSHParams(url, opener);

  // Use tree command with JSON output for recursive listing
  // -f: print full path prefix
  // -J: output in JSON format
  // Note: Don't use -h (human-readable sizes) as it might affect JSON parsing
  string command = "tree -f -J " + params.remote_path;
  fprintf(stderr, "[StorageBox SSH] Executing: %s\n", command.c_str());

  string output;
  try {
    output = ssh_client->ExecuteCommand(command);
    fprintf(stderr, "[StorageBox SSH] tree command returned %zu bytes\n",
            output.length());
  } catch (const std::exception &e) {
    fprintf(stderr, "[StorageBox SSH] tree command failed: %s\n", e.what());
    return {};
  }

  // Parse JSON output
  vector<TreeNode> root_nodes;
  size_t pos = 0;

  try {
    SkipWhitespace(output, pos);
    if (pos >= output.length() || output[pos] != '[') {
      throw IOException("Expected '[' at start of JSON output");
    }
    pos++;

    ParseTreeJSON(output, root_nodes, pos);

    fprintf(stderr, "[StorageBox SSH] Parsed %zu root nodes from tree output\n",
            root_nodes.size());
  } catch (const IOException &e) {
    fprintf(stderr, "[StorageBox SSH] Failed to parse tree JSON: %s\n",
            e.what());
    return {};
  }

  // Flatten the tree structure into a list of file paths
  vector<string> files;
  FlattenTreeNodes(root_nodes, "", files);

  fprintf(stderr, "[StorageBox SSH] Found %zu files via SSH tree\n",
          files.size());
  return files;
}

} // namespace duckdb
