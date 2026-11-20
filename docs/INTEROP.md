# Open standards and interoperability: sealed-storage-client

Modular Seal encryption client with a policy registry.

This page lists what the project speaks today, what is planned, what was considered and does not apply, where someone else can extend it, and what proves each claim. The platform-wide list is [Standards we use](https://meddleware.dev/platform/standards). A row appears there in the same change that turns a standard on.

## Spoken today

- Seal key-server threshold encryption (independent key servers on mainnet)
- A documented policy plug-in interface

## Planned

- A portable manifest format for sealed files (JSON) that other tools can read and write

## Considered, not applicable

- none

## Extension points

- New policies are plug-ins; key servers are configuration

## What proves it

- its unit tests
- the live Seal round trip before a release

_Maintained centrally with the platform's interoperability map; changes go through it so every repository says the same thing._
