# digdag-plugin-sshresult

Digdag ssh_result> operator plugin to execute a remote command via ssh and storing output of shell to digdag store.

This plugin is compatible with ssh plugin and ssh plugin and shresult plugin as long as it can.

Ssh Configuration is same as ssh plugin.
Storing Configuration is same as shresult plugin.

## Example

```

_export:
  ssh:
    host: host.add.re.ss
    user: username
    stdout_log: true # Output stdout log (default true)
    stderr_log: true # Output stderr log (default false)

+step1:
  ssh_result>: hostname
  destination_variable: resultset
  stdout_format: text

+step2:
  echo>: ${resultset}

```

## Development

### 1) build

```sh
./gradlew publish
```

Artifacts are build on local repos: `./build/repo`.

### 2) run an example

```sh
digdag selfupdate

rm -rf .digdag/plugin
digdag run -a --project sample plugin.dig -p repos=`pwd`/build/repo
```

## Maintainers

* Yuki Iwamoto(@yuhiwa)
