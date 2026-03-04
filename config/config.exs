import Config
config :logger, :console, level: :info
config :mnesia, dir: ~c"db/"

config :sshpot_ex, gotify_url: nil
