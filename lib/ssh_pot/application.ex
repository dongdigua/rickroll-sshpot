defmodule SSHPot.Application do
  use Application
  @impl true
  def start(_type, _args) do
    SSHPot.Db.init()

    children = [
      %{
        id: SSHPot,
        start: {SSHPot, :start_link, []}
      }
    ]

    opts = [strategy: :one_for_one, name: SSHPot.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
