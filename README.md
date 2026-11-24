# Pent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)

Run a program with almost no access. When it needs more, pent asks you
while it runs, and it remembers your answer.

> **Status:** this README describes the new design
> ([docs/design/pent.md](docs/design/pent.md)). Version 0.2.x still uses the
> old flow of `pent watch` and `pent trust`.

## Quick start

```bash
yay -S pent                 # Arch Linux; for Debian and Ubuntu, see below

pent run -w -- claude       # -w: the program may change the current directory
pent monitor                # in a second terminal: answer the questions
```

The first run asks more. Each answer becomes a rule, so the next run
asks less.

## How it works

- **The program starts with the base:** the system programs and libraries,
  `/etc`, and its own empty `/tmp`. Your home directory, the workspace, the
  network and the sockets of your machine are closed.
- **A new access waits for an answer.** The program does not see a
  difference, except the time.
- **The answers come from a chain:** your rules, then an optional local model,
  then you in `pent monitor`. A question that nobody answers in time fails
  like a refusal, and it stays open for the next run.
- **Each answer has a width:** one file, a directory, a subtree, or a domain
  such as `*.example.com`.
- **Pent never lies to the program.** It allows, refuses or asks. It does not
  write to the terminal of the program.
- **No root, no containers.** Pent uses Linux namespaces, Landlock, FUSE and
  a proxy for the network.

| The program wants to | Pent asks |
|---|---|
| read, write or run a file outside the base | "may claude read `~/.cargo/registry/**`?" |
| list a directory | "may claude list `~`?" |
| reach a domain | "may claude reach `api.anthropic.com`?" |
| connect to a Unix socket or a port on localhost | "may claude connect to `localhost:5432`?" |

**Sensitive paths** (keys, tokens, shell start files) and strong sockets
(Docker, `ssh-agent`) always go to you, with a warning. The model can only
recommend for them. The files of pent are never visible to the program.

## Agents

```bash
pent run -w -- claude
```

The agent and each program that it starts run in one sandbox. The agent
cannot allow anything. Inside the sandbox, `pent denials` shows what pent
refused, and `pent skip ID REASON` sends a question to you with a reason.

## Configuration

`~/.config/pent/pent.toml`:

```toml
# Optional: a local model (GGUF, at most 3B parameters) answers first.
[judge]
model = "~/.local/share/pent/models/MODEL.gguf"
mode  = "recommend"         # "auto": the model decides alone, except for sensitive paths

# Optional: a command that pent runs when questions wait.
[notify]
command = ["sh", "-c", "notify-send -A open=Open pent \"$PENT_PENDING programs need your attention\" | grep -q open && foot -e pent monitor"]
```

| Command | Description |
|---|---|
| `pent run [-w[=DIR]] -- CMD` | Run a command. `--read`, `--write`, `--allow DOMAIN` and the other flags answer in advance for one run. |
| `pent monitor` | Answer the questions. |
| `pent rules list` / `show KEY` / `forget KEY` | Read and change your rules. |
| `pent judge download NAME` | Download a tested model. |
| `pent daemon` | Run pentd in the foreground (it also starts on demand, or as a systemd user unit). |
| `pent check` | Show what your kernel gives. |

The rules are in `~/.local/state/pent/rules/`, one TOML file
for each program.

## Requirements

- Linux with Landlock (6.2 or later) and unprivileged user namespaces.
- `/dev/fuse`.
- `pent check` tells you what is missing.

## Install on Debian and Ubuntu

```bash
curl -fsSL https://valentinradu.github.io/Pent/apt/KEY.gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/pent.gpg
echo "deb [signed-by=/etc/apt/keyrings/pent.gpg arch=$(dpkg --print-architecture)] \
  https://valentinradu.github.io/Pent/apt ./" \
  | sudo tee /etc/apt/sources.list.d/pent.list
sudo apt update && sudo apt install pent
```

## Security

Pent is a guard rail, not a guarantee. For a program that you believe is
hostile, use a VM. [docs/security](docs/security/) holds the audit of the
current code.

## License

MIT, see [LICENSE](LICENSE).
