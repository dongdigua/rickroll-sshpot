# rickroll-sshpot
zero-dependency ssh rickrolling and honeypot platform.

## Running
run only rickroll
```sh
elixir roll.ex
```

run only honeypot
```sh
# ensure :port is NOT nil in config.exs
mix run --no-halt
```

run rickroll as a gateway to honeypot,
when client uses `password` instead of `keyboard-interactive` to login a PoW-protected rickroll after a certain frequency,
the honeypot will takeover
```sh
# ensure :port IS nil in config.exs
mix run roll.ex
```

## How it Works
`roll.ex` uses `Code.loaded?(SSHPot)` to detect whether the honeypot is present.

it also uses `publickey,keyboard-interactive,password`,
so a normal "user" will not try password authentication but a bot will.

the `:ssh.daemon` is run behind a `:gen_tcp` loop_acceptor,
when client meets certain condition, it will be dispatched to different `:ssh.daemon`.


## Table Structure
see [db.ex](./lib/ssh_pot/db.ex)

## Configuration
[roll.ex](./roll.ex):
`@port`,
`@system_dir`,
`@difficulty` (number of prefix zeros for PoW, 0 to disable),
`@threshold` (number of password login per minute before honeypot takeover)

[config.exs](./config/config.exs)

## Ref
- https://github.com/keroserene/rickrollrc
- https://github.com/lrstanley/rickroll-ssh
