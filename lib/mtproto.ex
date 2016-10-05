defmodule MTProto do
  use Application

  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    # Define workers and child supervisors to be supervised
    children = [
      # Starts a worker by calling: Mtproto.Worker.start_link(arg1, arg2, arg3)
      # worker(Mtproto.Worker, [arg1, arg2, arg3]),
      worker(MTProto.Conn, ['149.154.167.40'], restart: :temporary)
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: MTProto.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
