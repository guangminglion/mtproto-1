defmodule MTProto.Mixfile do
  use Mix.Project

  def project do
    [app: :mtproto,
     version: "0.1.0",
     elixir: "~> 1.3",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     test_coverage: [tool: ExCoveralls],
     preferred_cli_env: preferred_cli_env,
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    [applications: [:crypto, :connection, :tl]]
  end

  defp preferred_cli_env do
    ["coveralls": :test,
     "coveralls.detail": :test,
     "coveralls.post": :test,
     "coveralls.html": :test]
  end

  defp deps do
    [{:connection, "~> 1.0.4"},
     {:tl, "~> 57.1.0-rc"},
     {:mock, "~> 0.2.0", only: :test},
     {:excoveralls, "~> 0.5.7", only: :test},
     {:ex_doc, "~> 0.14", only: :dev},
     {:inch_ex, ">= 0.0.0", only: :dev}]
  end

  defp description do
    "MTProto transport for Elixir"
  end

  defp package do
    [maintainers: ["Yuri Artemev", "Alexander Malaev"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/ccsteam/mtproto"}]
  end
end
