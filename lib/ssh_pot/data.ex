defmodule SSHPot.Data do
  defp data_loop(:"$end_of_table", _fun, acc), do: acc

  defp data_loop(cur_key, fun, acc) do
    [{_tbl, _time, ip, user, pwd}] = :mnesia.dirty_read(:attempt, cur_key)
    data_loop(:mnesia.dirty_next(:attempt, cur_key), fun, fun.([ip: ip, user: user, pwd: pwd], acc))
  end

  def sort(idx) do
    fun = fn row, acc ->
      Map.update(acc, row[idx], 1, &(&1 + 1))
    end

    res = data_loop(:mnesia.dirty_first(:attempt), fun, %{})

    Enum.sort(Map.keys(res), &(res[&1] >= res[&2]))
    |> Enum.map(fn x -> {x, res[x]} end)
  end

  def find(idx, regex) do
    fun = fn row, acc ->
      if String.match?(row[idx], regex) do
        [row | acc]
      else
        acc
      end
    end

    data_loop(:mnesia.dirty_first(:attempt), fun, [])
  end

  def list_session(),
    do: :mnesia.table_info(:session, :wild_pattern) |> :mnesia.dirty_match_object()
end
