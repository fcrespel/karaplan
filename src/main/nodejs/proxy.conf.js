const PROXY_CONFIG = [
  {
    context: [
        "/api",
        "/oauth2",
        "/login/oauth2",
        "/logout",
        "/actuator",
        "/webjars",
        "/v2",
        "/swagger-resources",
        "/swagger-ui.html"
    ],
    target: "http://localhost:8080",
    secure: false
  }
]

module.exports = PROXY_CONFIG;
