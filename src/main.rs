use actix_session::{storage::CookieSessionStore, SessionExt, SessionMiddleware};
use actix_web::{
    cookie::Key,
    get, post,
    web::{self, Json, Query, Redirect},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use serde::{Deserialize, Serialize};

/**
You can get this value by running `edgedb instance credentials`.
Value should be:
`${protocol}://${host}:${port}/db/${database}/ext/auth/
**/
const EDGEDB_AUTH_BASE_URL: &str = "http://localhost:10746/db/edgedb/ext/auth";
const SERVER_PORT: u32 = 3000;

#[derive(Clone, Debug)]
struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    fn generate() -> Self {
        let mut verifier = String::new();
        let random: [u8; 32] = std::array::from_fn(|_| rand::random::<u8>());
        let verifier = base64_url::encode_to_string(&random, &mut verifier).to_string();

        let challenge = sha256::digest(verifier.clone());
        let challenge = base64_url::encode(&challenge);

        assert!(verifier.len() == 43);
        println!("Verifier: {verifier}\nChallenge: {challenge}");
        Self {
            verifier,
            challenge,
        }
    }
}

fn build_url(url: String, params: &[(&str, &str)]) -> String {
    let mut url = url::Url::parse(&url).unwrap();
    for (name, value) in params {
        url.query_pairs_mut().append_pair(name, value);
    }
    url.to_string()
}

//
// UI FLOW: https://www.edgedb.com/docs/guides/auth/built_in_ui
//

/// #[get("/auth/ui/signin")]
#[get("/auth/ui/signin")]
async fn handle_ui_signin(request: HttpRequest) -> impl Responder {
    let pkce = Pkce::generate();

    let redirect_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/ui/signin"),
        &[("challenge", &pkce.challenge)],
    );

    request
        .get_session()
        .insert("edgedb-pkce-verifier", pkce.verifier)
        .unwrap();
    Redirect::to(redirect_url)
}

/// #[get("/auth/ui/signup")]
#[get("/auth/ui/signup")]
async fn handle_ui_signup(request: HttpRequest) -> impl Responder {
    let pkce = Pkce::generate();

    let redirect_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/ui/signup"),
        &[("challenge", &pkce.challenge)],
    );

    request
        .get_session()
        .insert("edgedb-pkce-verifier", pkce.verifier)
        .unwrap();
    Redirect::to(redirect_url)
}

#[derive(Debug, Deserialize)]
struct HandleAuthorize {
    provider: String,
}

//
// AUTH FLOW: https://www.edgedb.com/docs/guides/auth/oauth
//

/// #[get("/auth/authorize")]
#[get("/auth/authorize")]
async fn handle_authorize(query: Query<HandleAuthorize>, request: HttpRequest) -> impl Responder {
    let HandleAuthorize { provider } = query.into_inner();
    let pkce = Pkce::generate();

    let redirect_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/authorize"),
        &[
            ("provider", &provider),
            ("challenge", &pkce.challenge),
            (
                "redirect_to",
                &format!("http://localhost:{SERVER_PORT}/auth/callback"),
            ),
        ],
    );

    request
        .get_session()
        .insert("edgedb-pkce-verifier", pkce.verifier)
        .unwrap();
    Redirect::to(redirect_url)
}

//
// EMAIL AND PASSWORD FLOW: https://www.edgedb.com/docs/guides/auth/email_password
//

#[derive(Debug, Deserialize)]
struct HandleSignup {
    email: String,
    password: String,
    provider: String,
}

#[derive(Debug, Serialize)]
struct Signup {
    challenge: String,
    email: String,
    password: String,
    provider: String,
    verify_url: String,
}

/// Handles sign up with email and password.
/// #[get("/auth/signup")]
#[get("/auth/signup")]
async fn handle_signup(query: Query<HandleSignup>, request: HttpRequest) -> impl Responder {
    let pkce = Pkce::generate();
    let HandleSignup {
        email,
        password,
        provider,
    } = query.into_inner();
    let register_url = build_url(format!("{EDGEDB_AUTH_BASE_URL}/register"), &[]);

    // Just used to see if the post succeeds, don't care about the return text?
    let _register_response = reqwest::Client::new()
        .post(register_url)
        .json(&Signup {
            challenge: pkce.challenge,
            email,
            password,
            provider,
            verify_url: format!("http://localhost:${SERVER_PORT}/auth/verify"),
        })
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    request
        .get_session()
        .insert("edgedb-pkce-verifier", pkce.verifier)
        .unwrap();

    // NoContent = 204
    HttpResponse::NoContent()
}

#[derive(Deserialize)]
struct HandleSignin {
    email: String,
    password: String,
    provider: String,
}

#[derive(Serialize, Deserialize)]
struct AuthenticateRequest {
    challenge: String,
    email: String,
    password: String,
    provider: String,
}

#[derive(Debug, Deserialize)]
struct AuthenticateResponse {
    code: String,
}

/// #[get("/auth/signin")]
#[get("/auth/signin")]
async fn handle_signin(query: Json<HandleSignin>, request: HttpRequest) -> impl Responder {
    let HandleSignin {
        email,
        password,
        provider,
    } = query.into_inner();
    let authenticate_url = format!("{EDGEDB_AUTH_BASE_URL}/authenticate");
    let pkce = Pkce::generate();

    let authenticate_response: AuthenticateResponse = reqwest::Client::new()
        .post(authenticate_url)
        .json(&AuthenticateRequest {
            challenge: pkce.challenge,
            email,
            password,
            provider,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let token_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/token"),
        &[
            ("code", &authenticate_response.code),
            ("verifier", &pkce.verifier),
        ],
    );

    let auth_token = reqwest::get(&token_url.to_string())
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    request
        .get_session()
        .insert("edgedb-auth-token", auth_token)
        .unwrap();

    // NoContent = 204
    HttpResponse::NoContent()
}

#[derive(Debug, Deserialize)]
struct HandleVerify {
    verification_token: String,
}

#[derive(Debug, Serialize)]
struct Verify {
    verification_token: String,
    verifier: String,
    provider: &'static str,
}

/// Handles the link in the email verification flow.
/// #[get("/auth/verify")]
#[get("/auth/verify")]
async fn handle_verify(query: Query<HandleVerify>, request: HttpRequest) -> impl Responder {
    let HandleVerify { verification_token } = query.into_inner();

    let session = request.get_session();
    let verifier: String = session.get("edgedb-pkce-verifier").unwrap().unwrap();

    let verify_url = format!("{EDGEDB_AUTH_BASE_URL}/verify");
    let code = reqwest::Client::new()
        .post(verify_url)
        .json(&Verify {
            verification_token,
            verifier: verifier.clone(),
            provider: "builtin::local_emailpassword",
        })
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let token_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/token"),
        &[("code", &code), ("verifier", &verifier)],
    );

    let auth_token = reqwest::get(token_url).await.unwrap().text().await.unwrap();

    session.insert("edgedb-auth-token", auth_token).unwrap();
    // NoContent = 204
    HttpResponse::NoContent()
}

#[derive(Debug, Deserialize)]
struct HandleSendPasswordResetEmail {
    email: String,
}

#[derive(Debug, Serialize)]
struct SendResetUrl {
    email: String,
    provider: String,
    reset_url: String,
    challenge: String,
}

#[derive(Debug, Deserialize)]
struct SendResetResponse {
    email_sent: String,
}

/// #[get("/auth/send-password-reset-email")]
#[get("/auth/send-password-reset-email")]
async fn handle_send_password_reset_email(
    reset: Query<HandleSendPasswordResetEmail>,
) -> impl Responder {
    let HandleSendPasswordResetEmail { email } = reset.into_inner();
    let reset_url = build_url(
        format!("http://localhost:${SERVER_PORT}/auth/ui/reset-password"),
        &[],
    );
    let provider = "builtin::local_emailpassword".to_string();
    let pkce = Pkce::generate();
    let send_reset_url = build_url(format!("{EDGEDB_AUTH_BASE_URL}/send-reset-url"), &[]);

    let SendResetResponse { email_sent } = reqwest::Client::new()
        .post(send_reset_url)
        .json(&SendResetUrl {
            email,
            provider,
            reset_url,
            challenge: pkce.challenge,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    HttpResponse::Ok().body(format!("Reset email sent to {email_sent}"))
}

#[derive(Debug, Deserialize)]
struct HandleUiResetPassword {
    reset_token: String,
}

/// Render a simple reset password UI
/// #[get("/auth/ui/reset-password")]
#[get("/auth/ui/reset-password")]
async fn handle_ui_reset_password(query: Query<HandleUiResetPassword>) -> impl Responder {
    let HandleUiResetPassword { reset_token } = query.into_inner();
    HttpResponse::Ok().body(format!(
        r#"<html>
             <body>
               <form method="POST" action="http://localhost:${SERVER_PORT}/auth/reset-password">
                 <input type="hidden" name="reset_token" value="${reset_token}">
                 <label>
                   New password:
                   <input type="password" name="password" required>
                 </label>
                 <button type="submit">Reset Password</button>
               </form>
             </body>
           </html>"#
    ))
}

#[derive(Debug, Deserialize)]
struct HandleResetPassword {
    reset_token: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct ResetRequest {
    reset_token: String,
    password: String,
    provider: &'static str,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    auth_token: String,
}

#[derive(Debug, Deserialize)]
struct ResetResponse {
    code: String
}

/// #[post("/auth/reset-password")]
/// Send new password with reset token to EdgeDB Auth.
#[post("/auth/reset-password")]
async fn handle_reset_password(
    query: web::Json<HandleResetPassword>,
    request: HttpRequest,
) -> impl Responder {
    let HandleResetPassword {
        reset_token,
        password,
    } = query.into_inner();

    let reset_url = format!("{EDGEDB_AUTH_BASE_URL}/reset-password");
    let verifier: String = request.get_session().get("edgedb-pkce-verifier").unwrap().unwrap();
    let reset_response: ResetResponse = reqwest::Client::new()
        .post(reset_url)
        .json(&ResetRequest {
            reset_token,
            password,
            provider: "builtin::local_emailpassword",
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let token_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/token"),
        &[("code", &reset_response.code), ("verifier", &verifier)],
    );

    // What should the auth_token struct look like?
    let TokenResponse { auth_token } = reqwest::get(token_url).await.unwrap().json().await.unwrap();
    println!("TokenResponse auth_token: {auth_token}");

    request
        .get_session()
        .insert("edgedb-auth-token", auth_token)
        .unwrap();

    // 204
    HttpResponse::NoContent()
}

#[derive(Debug, Deserialize)]
struct HandleCallback {
    code: String,
}

// HANDLE CALLBACK: same for all
/// #[get("/auth/callback")]
#[get("/auth/callback")]
async fn handle_callback(response: Query<HandleCallback>, request: HttpRequest) -> impl Responder {
    let session = request.get_session();
    println!("Session cookies: {:#?}", session.entries());
    println!("Got a {response:?}");

    let HandleCallback { code } = response.into_inner();
    let verifier: String = session.get("edgedb-pkce-verifier").unwrap().unwrap();
    println!("Here's the verifier! {verifier}");

    let code_exchange_url = build_url(
        format!("{EDGEDB_AUTH_BASE_URL}/token"),
        &[("code", &code), ("verifier", &verifier)],
    );
    println!("The code exchange url is: {}", code_exchange_url);

    let code_exchange_response = reqwest::get(&code_exchange_url.to_string())
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    println!("Exchange response: {code_exchange_response:?}");
    let auth_token = code_exchange_response;

    request
        .get_session()
        .insert("edgedb-auth-token", auth_token)
        .unwrap();

    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone()) // Others already set by default: http_only, secure, and path "/"
                    // .cookie_same_site(actix_web::cookie::SameSite::Strict) - Why does setting this cause the session to disappear?
                    .build(),
            )
            // UI FLOW
            .service(handle_ui_signin)
            .service(handle_ui_signup)
            .service(handle_callback)
            // OAUTH FLOW
            .service(handle_authorize)
            // EMAIL FLOW
            .service(handle_signup)
            .service(handle_signin)
            .service(handle_verify)
            .service(handle_send_password_reset_email)
            .service(handle_ui_reset_password)
            .service(handle_reset_password)
    })
    .bind(&format!("127.0.0.1:{SERVER_PORT}"))
    .unwrap()
    .run()
    .await
}