# Project Instructions

Your goal is to be able to stream small chunks of data as duckdb creates it into buffers. You want to have https ssh connections which stay alive so that you don't need to do the handshake everytime.

There are already 2 ways to interact with Hetzner Storage boxes:
* ../duckdb-webdav
* ../ducdkb-sshfs

Webdav is significantly faster on reading small ranges from the parquet files and the ssh overhead is a lot for that kind of requests.

Duckdb http_util doesn't support overriding the HTTP verbs to MKCOL and PROPFIND so we can't use it.

ssh has support on recursively globbing all files with:
```
ssh storagebox "tree -f -h -J ./ducklake"
```

ssh can create parent directories in one go:
```
ssh storagebox "mkdir -p ./folder/another/third/fourth"
```

Webdav needs to do recursive MKCOL commands.

## Important Security Notice

Do not commit IP-addresses, usernames or passwords to git

## Development Environment

This project is using devenv for the development environment, dependencies and for git hooks. See more in ./devenv.nix

## Documentation

Do not create separate markdown files. Only use ./README.md and check that it's always consistent with the project state.

## Testing with curl

Here are some examples of how webdav works with curl

### Create folder

```sh
curl -X MKCOL --user '$STORAGEBOX_USER:$STORAGEBOX_PASSWORD' https://$STORAGEBOX_USER.your-storagebox.de/folder/
```

### List files

```sh
curl -X PROPFIND -H "Depth: 1" --user '$STORAGEBOX_USER:$STORAGEBOX_PASSWORD' https://$STORAGEBOX_USER.your-storagebox.de/folder/
```

# SSH
Hetzner Storage boxes which have only limited ssh connections available.

You have ssh keys in:
* /Users/onnimonni/.ssh/storagebox_key
* /Users/onnimonni/.ssh/storagebox_key.pub

You can login with:
```sh
$ ssh -o IdentityAgent=none -i ~/.ssh/storagebox_key -p23 u508112@u508112.your-storagebox.de
```

Or with password `reesh5beiYohth8z_WohX7ka7le7Mahqu`

## Available commands

You can list all available commands and server backends:

```sh
$ ssh -o IdentityAgent=none -i ~/.ssh/storagebox_key -p23 u508112@u508112.your-storagebox.de "help"
```

### Get more info on certain command

```sh
$ ssh -o IdentityAgent=none -i ~/.ssh/storagebox_key -p23 u508112@u508112.your-storagebox.de "dd --help"
```

### Testing performance
Test for performance regressions between each change by writing a large parquet file >100Mb and reading a small section from that. If performance is slower try again to rule out network issues. 

Try to solve the performance issues but if you can't solve them then inform to the user that you couldn't figure it out and revert changes.