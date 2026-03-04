defmodule SSHPot.FakeCli do
  @compile_time DateTime.utc_now() |> Calendar.strftime("%a, %d %b %Y %H:%M:%S +0000")

  @command_io_map %{
    "cat" => " /\\_/\\\n( o.o )\n > ^ <",
    "whoami" => "root",
    "pwd" => "/Never/Gonna/Give/You/Up",
    "uname" =>
      "Linux rhel 6.12.0-124.8.1.el10_1.x86_64 #1 SMP PREEMPT_DYNAMIC #{@compile_time} x86_64 GNU/Linux"
  }

  def cli(0, acc), do: acc

  def cli(count, acc) do
    case IO.gets("[root@rhel]# ") do
      :eof ->
        IO.puts("logout")
        acc

      {:error, :interrupted} ->
        IO.puts("^C")
        cli(count - 1, acc)

      input_raw ->
        input = input_raw |> to_string() |> String.trim()
        command = List.first(String.split(input))

        case command do
          "exit" ->
            acc

          "quit" ->
            acc

          _ ->
            IO.puts(@command_io_map[command])
            cli(count - 1, acc ++ [input])
        end
    end
  end

  def exec(input_raw) do
    input = input_raw |> to_string() |> String.trim()
    command = List.first(String.split(input))

    if Map.has_key?(@command_io_map, command) do
      IO.puts(@command_io_map[command])
    else
      IO.puts("bash: #{command}: command not found")
    end
  end
end
