defmodule SSHPot do
  require Logger
  @sys_dir String.to_charlist(Path.expand(".") <> "/ssh")
  @port 2222

  def set_random_login(n) do
    Application.put_env(:sshpot_ex, :random_login, n)
  end

  def start_link do
    Logger.info("Starting... timestamp: #{System.os_time()}")

    {:ok, _} = :ssh.daemon(@port,
      system_dir: @sys_dir,
      id_string: ~c"OpenSSH_10.2",
      shell: &shell/2,
      pwdfun: &log_passwd/4,
      auth_methods: ~c"password",
      exec: &exec/3
    )

    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  def exec(cmd, username, peer) do
    spawn(fn ->
      SSHPot.FakeCli.exec(cmd)
      finalize_session(username, peer, [List.to_string(cmd)])
    end)
  end

  def shell(username, peer) do
    spawn(fn ->
      commands = SSHPot.FakeCli.cli(5, [])
      IO.puts(IO.ANSI.red() <> "You Muffin Head!" <> IO.ANSI.reset())
      finalize_session(username, peer, commands)
    end)
  end

  defp finalize_session(username, peer, commands) do
    key = {List.to_string(username), peer}

    {user, passwd, ip} =
      Agent.get_and_update(__MODULE__, fn state ->
        val = Map.get(state, key)
        {val, Map.delete(state, key)}
      end) || {"unknown", "unknown", format_ip(peer)}

    SSHPot.Db.append_commands(user, passwd, commands)
    spawn(fn -> send_gotify(ip, user, passwd, commands) end)
  end

  defp send_gotify(ip, user, passwd, commands) do
    case Application.get_env(:sshpot_ex, :gotify_url) do
      nil ->
        :ok

      url ->
        message =
          "User: #{user}\nPass: #{passwd}\nIP: #{ip}\nCommands:\n#{Enum.join(commands, "\n")}"

        params = %{"title" => "SSH Pot Alert", "message" => message, "priority" => 5}
        body = URI.encode_query(params)

        headers = []
        content_type = ~c"application/x-www-form-urlencoded"

        # httpc expects charlists for URL and Content-Type
        request = {String.to_charlist(url), headers, content_type, String.to_charlist(body)}

        case :httpc.request(:post, request, [], []) do
          {:ok, {{_, 200, _}, _, _}} -> Logger.info("Gotify notification sent")
          {:ok, {{_, status, _}, _, _}} -> Logger.error("Gotify returned status #{status}")
          {:error, reason} -> Logger.error("Gotify error: #{inspect(reason)}")
        end
    end
  end

  defp format_ip({ip_tuple, _port}) do
    ip_tuple |> :inet.ntoa() |> List.to_string()
  end

  def log_passwd(user, passwd, peer, _) do
    user = List.to_string(user)
    passwd = List.to_string(passwd)
    ip = format_ip(peer)
    Logger.info("#{user},#{passwd} from #{ip}")

    SSHPot.Db.log_attempt(ip, user, passwd)

    known_user = SSHPot.Db.session_exists?(user, passwd)

    # login success if known or randomly
    if known_user || :rand.uniform(Application.get_env(:sshpot_ex, :random_login, 1000)) == 6 do
      Logger.warning("Login success (Known: #{known_user})")

      # Ensure session is registered
      SSHPot.Db.register_session(user, passwd)

      Agent.update(__MODULE__, fn state ->
        Map.put(state, {user, peer}, {user, passwd, ip})
      end)

      true
    else
      false
    end
  end
end
