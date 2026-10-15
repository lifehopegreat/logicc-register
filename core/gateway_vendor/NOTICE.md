# Embedded Logicc adapter

The four `.mjs` files in this directory are vendored, unmodified from
[JamesZhaoY/logicc2api](https://github.com/JamesZhaoY/logicc2api), version 1.3.0,
commit `3c57a737960f5515efec88e4b0381fa3614c8fe8`.
Copyright (c) 2026 JamesZhaoY. Distributed under the included MIT LICENSE.

Only the reusable adapter modules are included. No upstream account data,
configuration, dashboard assets, deployment files or dependencies are included.
The parent project's supervised worker adds encrypted storage, internal
authentication, a route allowlist and a bounded concurrency limit. Its public
API exposes OpenAI Chat Completions and Responses, not Anthropic Messages.
