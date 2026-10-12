// Package models is the wire contract for the KNIRVMODELS daemon: request and
// response types, the byte-v1 tokenizer, the supervisor-advice rules, and typed
// clients (TCP or unix socket). It has no dependencies, so backend_server and
// KNIRVINFERENCER can talk to every model without linking the models module.
//
// The same contract exists in TypeScript (npm-package/src/models). Both are
// tested against the JSON fixtures in testvectors/models so they cannot drift
// silently.
package models
