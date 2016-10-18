### [MTProto](https://core.telegram.org/mtproto) transport for Elixir [![Hex.pm](https://img.shields.io/hexpm/v/mtproto.svg)](https://hex.pm/packages/mtproto) [![Travis](https://img.shields.io/travis/ccsteam/mtproto.svg)](https://travis-ci.org/ccsteam/mtproto)

---

MTProto (protocol) transport implementation in Elixir, acts like gen_tcp and others, supports most service commands.

---

### TODO

* Tests, more testing;
* Add checks for numbers in DH algorithm;
* Checks for salts and nonce hashes during authorization;
* Data Center migration;
* Fix handling msg_seqno (?).

---

## Installation

1. Add `mtproto` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:mtproto, "~> 57.0.0-alpha"}]
end
```

2. Ensure `mtproto` is started before your application:

```elixir
def application do
  [applications: [:mtproto]]
end
```

---

### Usage

...

---

### Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
