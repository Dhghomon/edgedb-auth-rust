# edgedb-auth-rust
Porting https://www.edgedb.com/docs/guides/auth/index to Rust

* UI flow mostly works except the verifier and challeng don't match at the end: Pkce::generate() is probably wrong
* Working on other flows atm
* Actix_session seems to be the easiest way to handle the cookies https://docs.rs/actix-session/latest/actix_session/
