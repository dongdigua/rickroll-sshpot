defmodule SSHPot.Db do
  require Logger

  # first create a schema on disc using erl -mnesia dir <DIR>
  # then mnesia:create_schema([node()]).
  def init do
    tables = :mnesia.system_info(:tables)

    # Initialize :attempt table
    if :attempt in tables do
      Logger.info("Table :attempt already exists.")
    else
      Logger.info("Creating table :attempt...")
      :mnesia.create_table(:attempt,
        attributes: [:time, :ip, :user, :passwd],
        disc_copies: [node()],
        type: :ordered_set
      )
    end

    # Initialize :session table
    if :session in tables do
      Logger.info("Table :session already exists.")
    else
      Logger.info("Creating table :session...")
      :mnesia.create_table(:session,
        attributes: [:user_pass, :commands],
        disc_copies: [node()],
        type: :set
      )
    end

    :mnesia.wait_for_tables([:attempt, :session], 5000)
  end

  def log_attempt(ip, user, passwd) do
    time_str = DateTime.utc_now() |> DateTime.to_iso8601()
    trans = fn ->
      :mnesia.write({
        :attempt,
        time_str,
        ip,
        user,
        passwd
      })
    end
    :mnesia.transaction(trans)
  end

  def session_exists?(user, passwd) do
    key = {user, passwd}
    case :mnesia.dirty_read(:session, key) do
      [] -> false
      _ -> true
    end
  end

  def register_session(user, passwd) do
    key = {user, passwd}
    trans = fn ->
      case :mnesia.read(:session, key) do
        [] -> :mnesia.write({:session, key, []})
        _ -> :ok
      end
    end
    :mnesia.transaction(trans)
  end

  def append_commands(user, passwd, commands) when is_list(commands) do
    key = {user, passwd}
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    
    new_cmds = Enum.map(commands, fn cmd -> {timestamp, cmd} end)

    trans = fn ->
      case :mnesia.read(:session, key) do
        [{:session, ^key, old_cmds}] ->
          :mnesia.write({:session, key, old_cmds ++ new_cmds})
        [] ->
          # Should not happen if registered, but auto-register fallback
          :mnesia.write({:session, key, new_cmds})
      end
    end
    :mnesia.transaction(trans)
  end
end
