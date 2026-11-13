// Package cgcom is everything the clinic needs to integrate with CGCOM's
// DoctorID physician enrolment, and nothing else of the clinic:
//
//   - the enrolment API client and its contract types (client.go, model.go);
//   - the platform credential: an ES256 key pair whose public half is
//     registered with CGCOM as a JWK (key.go), and the access token obtained
//     with it by private_key_jwt, RFC 7523 (token.go);
//   - the signature of the webhook notifications (signature.go) and a
//     sender for tests and the simulator (sender.go).
//
// What the clinic does with it (its records, screens and access rule) lives
// in other packages.
package cgcom
