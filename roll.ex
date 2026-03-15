defmodule RickRoll do
  require Logger
  @frame_time 40
  @frame_height 32
  @rick "./astley80.full"
  @port 2233
  @system_dir ~c"./ssh"

  def start() do
    Logger.configure(level: :info)
    :ok = :ssh.start()
    IO.inspect :erlang.memory

    if Code.loaded?(SSHPot) do
      spawn(&accept/0)
    else
      accept()
    end
  end

  def accept() do
    # inet6 is fine since OS uses dual-stack
    {:ok, socket} =
      :gen_tcp.listen(@port, [:inet, packet: 0, active: false, reuseaddr: true])
    {:ok, _} =
      Agent.start_link(fn -> %{} end, name: :pubkey_store)
    {:ok, _} =
      RickRoll.KbInt.start()
    {:ok, _} =
      RickRoll.Tracker.start()
    Logger.info("Listening on #{@port}")
    loop_acceptor(socket)
  end

  defp loop_acceptor(socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    # 为了识别用户，得套一层 gen_tcp
    pid = spawn(fn ->
      case :inet.peername(client) do
        {:ok, {ip, _}} ->
          if RickRoll.Tracker.should_banish?(ip) do
            Logger.info("Banish #{inspect(ip)} to honeypot")
            SSHPot.daemon(client)
          else
            rickroll(client)
          end
        _ ->
          :gen_tcp.close(client)
      end
    end)
    :gen_tcp.controlling_process(client, pid) # socket ownership
    loop_acceptor(socket)
  end

  defp rickroll(client) do
    {:ok, {ip, _}} = :inet.peername(client)
    Logger.info("Got victim #{List.to_string(:inet.ntoa(ip))}, memMB: #{:erlang.float_to_binary(:erlang.memory(:total)/1048576, [decimals: 2])}")
    :ssh.daemon(client, [
          system_dir: @system_dir,
          id_string: ~c"SSH-2.0-OpenSSH_RickRoll",
          max_sessions: 1,
          shell: &roll(&1, client),
          # keyboard-interactive for optional PoW, password for trapping bots
          auth_methods: ~c"publickey,keyboard-interactive,password",
          auth_method_kb_interactive_data: &RickRoll.KbInt.kb_int_fun/3,
          pwdfun: &RickRoll.KbInt.pwdfun/4,
          # log every key
          key_cb: {RickRoll.KeyCb, [client: client]},
        ])
  end

  defmodule Tracker do
    @threshold 10
    @window 60

    def start(), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

    def mark(ip) do
      now = :os.system_time(:seconds)
      Agent.update(__MODULE__, fn state ->
        timestamps = Map.get(state, ip, [])
        Map.put(state, ip, [now | timestamps])
      end)
    end

    def should_banish?(ip) do
      now = :os.system_time(:seconds)
      cutoff = now - @window

      Code.loaded?(SSHPot) and Agent.get_and_update(__MODULE__, fn state ->
        timestamps = Map.get(state, ip, [])
        recent = Enum.filter(timestamps, &(&1 > cutoff))

        is_banned = length(recent) > @threshold

        new_state = if recent == [] do
          Map.delete(state, ip)
        else
          Map.put(state, ip, recent)
        end
        {is_banned, new_state}
      end)
    end
  end

  defmodule KeyCb do
    @behaviour :ssh_server_key_api

    def host_key(algorithm, options) do
      # fallback
      :ssh_file.host_key(algorithm, options)
    end

    def is_auth_key(pk, user, options) do
      client = options[:key_cb_private][:client]
      encoded = :ssh_file.encode([{pk, [comment: user]}], :openssh_key) |> String.trim
      Logger.info(encoded)
      Agent.update(:pubkey_store, fn state ->
        Map.update(state, client, [encoded], fn l -> [encoded|l] end)
      end)
      false
    end
  end

  defmodule KbInt do
    @difficulty 4 # 0 to disable PoW
    @prefix String.duplicate("0", @difficulty)

    def start(), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

    def kb_int_fun(peer, _user, _service) when @difficulty > 0 do
      nonce = :crypto.strong_rand_bytes(16) |> :binary.encode_hex()
      Agent.update(__MODULE__, fn state -> Map.put(state, peer, nonce) end)
      {"Making sure you are a robot", "SM3('#{nonce}'+?) == #{@prefix}...", "? = ", true}
    end

    def kb_int_fun(_peer, _user, _service) do
      {"", "", "password: ", false}
    end

    def pwdfun(user, pass, {ip, _} = peer, _state) when @difficulty > 0 do
      nonce = Agent.get(__MODULE__, fn state -> Map.get(state, peer) end)

      if is_nil(nonce) do
        # 没经过 kb_int 流程（即直接用了 password 认证），视为扫描
        Logger.warning("Bot detected: Direct password attempt: #{List.to_string(:inet.ntoa(ip))},#{user},#{pass}")
        RickRoll.Tracker.mark(ip)
        if RickRoll.Tracker.should_banish?(ip) do
          :disconnect
        else
          false
        end
      else
        # 正常的 PoW 流程
        Agent.update(__MODULE__, fn state -> Map.delete(state, peer) end)
        Logger.info("PoW: #{pass}")

        hash = :crypto.hash(:sm3, nonce <> IO.chardata_to_string(pass)) |> :binary.encode_hex()
        if String.starts_with?(hash, @prefix) do
          true
        else
          :disconnect
        end
      end
    end

    def pwdfun(_user, pass, _peer_or_state, _state_or_missing) do
      Logger.info("password: #{pass}")
      true
    end
  end

  defp print_pubkey(client) do
    IO.puts IO.ANSI.reset
    IO.puts "Your pubkeys:"
    Agent.get(:pubkey_store, fn x -> Map.get(x, client) end) |> Enum.each(&IO.puts(&1))
    IO.puts "#{IO.ANSI.red}Identity noted. Expect a visit soon!#{IO.ANSI.reset}"
  end

  def roll(_user, client) do
    spawn(fn ->
      parent = self()
      spawn(fn ->
        loop = fn loop ->
          case IO.gets("") do
            {:error, :interrupted} ->
              print_pubkey(client)
              Process.exit(parent, "")
            {:error, :terminated} -> :ok
            what ->
              Logger.info inspect(what)
              loop.(loop)
          end
        end
        loop.(loop)
      end)

      File.stream!(@rick, read_ahead: 16384 * 4)
      |> Stream.chunk_every(@frame_height)
      |> Stream.each(fn frame ->
        frame
        |> Enum.join # roughly 16384 in size
        |> IO.write
        Process.sleep(@frame_time)
      end)
      |> Stream.run()

      print_pubkey(client)
    end)
  end
end

RickRoll.start()
