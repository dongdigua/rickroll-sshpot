import Config
config :logger, :console, level: :info
config :mnesia, dir: ~c"db"

config :sshpot_ex,
  system_dir: ~c"ssh",
  gotify_url: nil,
  port: nil
