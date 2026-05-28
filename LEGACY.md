# Legacy CLI branch

This branch is the v1 single-binary quokka CLI, frozen at commit `ed2a363`
(the tip of `main` before the SaaS rewrite began).

Active development continues on `main`, which is now a self-hosted SaaS:
GitHub App integration, web UI for triage and configuration, BYOK multi-provider
LLM driver, per-run container isolation, persistent embedding state per repo.

This branch stays available for users who want the original CLI workflow
(`quokka init`, `quokka onboard`, `quokka review pr`, `quokka semantic`, etc.).
It receives security backports only; no new features.

The full SaaS plan lives at `~/.claude/plans/fluttering-kindling-swan.md`
on the author's machine.
