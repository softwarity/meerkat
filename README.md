# Meerkat

> The sentinel at your application's door.

**Meerkat** is an **app-gateway**: the single entry point for enterprise internal
applications. Unlike a classic API gateway, it is built to *serve an application* — it takes
care of everything that is common to all your services and none of your team's core business:

- **Authentication** — login pages served by the gateway, passwordless first (passkeys,
  TOTP, email OTP), enterprise methods (OIDC, LDAP, SAML) limited to authentication only
- **Authorization** — roles, role groups, per-route and per-endpoint access control
- **Multi-tenancy** — organizations, members, groups, tenant switching
- **Routing** — dynamic routes over a service catalog discovered in your cluster, hot reload,
  versioned configurations (duplicate, diff, switch, rollback)
- **Built-in, no extra tooling** — API quotas, audit log, observability dashboards: in the
  console, not in a YAML file, with no Prometheus/Grafana required
- **Dev mode** — with [`softwarity/plug`](https://github.com/softwarity/plug), a developer's
  workstation joins the cluster: their local service substitutes the deployed one for their
  own traffic, and testers can opt in to try a dev's variant
- **Zero dependency** — a single binary with embedded storage; an external database only if
  you want a HA cluster

Your services stay lean: they receive requests already authenticated, carrying a signed JWT
with identity, roles and tenant.

Meerkat is the successor of [Archway](https://github.com/softwarity/archway), rebuilt from
the ground up, and is edited by **[Softwarity](https://softwarity.io)**.

## Status

🚧 **Specification phase.** The full requirements document (currently in French) is in
[requirements.md](./requirements.md). Implementation has not started yet.

## Why "Meerkat"?

The meerkat is nature's sentinel: it stands guard at the burrow entrance and raises the
alert, so the rest of the colony can work without worrying about anything. That is exactly
what this gateway does for your services. Even the `plug` tunnel fits the picture — it is how
a developer's machine digs its way into the burrow. And since a group of meerkats is called a
*mob*, you already know what to call a cluster of Meerkat nodes.

## License

[FSL-1.1-Apache-2.0](./LICENSE.md) (Functional Source License): free to use, copy, modify and
redistribute for any purpose except building a competing product or service — internal and
production use in your company is explicitly permitted. Each release automatically becomes
**Apache 2.0 two years** after its publication.
