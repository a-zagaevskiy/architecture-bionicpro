#pragma once

#include <jwt-cpp/jwt.h>

#include <stdexcept>
#include <userver/clients/http/client.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/clients/http/form.hpp>
#include <userver/components/component.hpp>
#include <userver/components/component_base.hpp>
#include <userver/dynamic_config/source.hpp>
#include <userver/dynamic_config/value.hpp>
#include <userver/formats/json.hpp>
#include <userver/utils/async.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

namespace api {

using namespace userver;

class KeycloakClient {
 public:
  KeycloakClient(const std::string& server_url, const std::string& realm,
                 const std::string& client_id, const std::string& client_secret,
                 clients::http::Client& http_client)
      : server_url_(server_url),
        realm_(realm),
        client_id_(client_id),
        client_secret_(client_secret),
        http_client_(http_client),
        jwks_url_(server_url + "/realms/" + realm +
                  "/protocol/openid-connect/certs"),
        token_url_(server_url + "/realms/" + realm +
                   "/protocol/openid-connect/token"),
        userinfo_url_(server_url + "/realms/" + realm +
                      "/protocol/openid-connect/userinfo") {}

  std::string GetToken(const std::string& code,
                       const std::string& redirect_uri) {
    // TODO(a-zagaevskiy): impl is not verified!

    clients::http::Form form;
    form.AddContent("grant_type", "authorization_code");
    form.AddContent("code", code);
    form.AddContent("redirect_uri", redirect_uri);
    form.AddContent("client_id", client_id_);
    form.AddContent("client_secret", client_secret_);

    auto response = http_client_.CreateRequest()
                        .post(token_url_)
                        .form(std::move(form))
                        .retry(1)
                        .timeout(std::chrono::seconds(5))
                        .perform();

    if (response->status_code() != 200) {
      throw std::runtime_error("Failed to get token: " + response->body());
    }

    const auto json = formats::json::FromString(response->body());
    return json["access_token"].As<std::string>();
  }

  formats::json::Value VerifyToken(const std::string& token) {
    // Get JWKS (keys for token signature verification)
    auto response = http_client_.CreateRequest()
                        .get(jwks_url_)
                        .retry(1)
                        .timeout(std::chrono::seconds(5))
                        .perform();

    if (response->status_code() != 200) {
      throw std::runtime_error("Failed to fetch JWKS");
    }

    const auto jwk_set = [&]() {
      try {
        return jwt::parse_jwks(response->body());
      } catch (const std::exception& e) {
        // std::cerr << "Failed to parse JWKS: " << e.what() << '\n';
        throw std::runtime_error(std::string("Failed to parse JWKS: ") +
                                 e.what());
      }
    }();

    // Decode and verify token
    auto decoded = [&]() {
      try {
        return jwt::decode(token);
      } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Failed to decode token: ") +
                                 e.what());
      }
    }();

    auto kid = decoded.get_key_id();

    // Find key in JWKS by kid
    auto jwk = jwk_set.get_jwk(kid);
    auto x5c = jwk.get_x5c_key_value();
    if (!x5c.empty()) {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256(
          jwt::helper::convert_base64_der_to_pem(x5c), "", "", "")); // TODO: check other claims (if needed)

      verifier.verify(decoded);
    } else {
      const auto modulus = jwk.get_jwk_claim("n").as_string();
      const auto exponent = jwk.get_jwk_claim("e").as_string();
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256(
          jwt::helper::create_public_key_from_rsa_components(
              modulus,
              exponent)));  // TODO: check other claims (if needed)
      verifier.verify(decoded);
    }
    return formats::json::FromString(decoded.get_payload());
  }

  formats::json::Value GetUserInfo(const std::string& token) {
    // TODO(a-zagaevskiy): impl is not verified!
    auto response = http_client_.CreateRequest()
                        .get(userinfo_url_)
                        .headers({{"Authorization", "Bearer " + token}})
                        .retry(1)
                        .timeout(std::chrono::seconds(5))
                        .perform();

    if (response->status_code() != 200) {
      throw std::runtime_error("Failed to fetch userinfo: " + response->body());
    }
    // std::cerr << "!!!!!!!!! user info:" << response->body() << std::endl;
    return formats::json::FromString(response->body());
  }

 private:
  std::string server_url_;
  std::string realm_;
  std::string client_id_;
  std::string client_secret_;
  clients::http::Client& http_client_;
  std::string jwks_url_;
  std::string token_url_;
  std::string userinfo_url_;
};

class KeycloakAuthComponent final : public components::ComponentBase {
 public:
  static constexpr std::string_view kName = "keycloak-auth";

  KeycloakAuthComponent(const components::ComponentConfig& config,
                        const components::ComponentContext& context)
      : components::ComponentBase(config, context),
        http_client_(
            context.FindComponent<components::HttpClient>().GetHttpClient()),
        keycloak_client_(config["keycloak_url"].As<std::string>(),
                         config["realm"].As<std::string>(),
                         config["client_id"].As<std::string>(),
                         config["client_secret"].As<std::string>(),
                         http_client_) {}

  formats::json::Value GetUserInfo(const std::string& token) {
    return utils::Async(
               "keycloak_userinfo",
               [this, token] { return keycloak_client_.GetUserInfo(token); })
        .Get();
  }

  formats::json::Value VerifyToken(const std::string& token) {
    return utils::Async(
               "keycloak_verify",
               [this, token] { return keycloak_client_.VerifyToken(token); })
        .Get();
  }

  static yaml_config::Schema GetStaticConfigSchema() {
    return yaml_config::MergeSchemas<components::ComponentBase>(R"(
type: object
description: Keycloak OpenID Connect client
additionalProperties: false
properties:
    keycloak_url:
        type: string
        description: URL of Keycloak server (i.e. "http://localhost:8080")
    realm:
        type: string
        description: Name of realm in Keycloak
    client_id:
        type: string
        description: Client ID
    client_secret:
        type: string
        description: Client Secret
)");
  }

 private:
  clients::http::Client& http_client_;
  KeycloakClient keycloak_client_;
};

}  // namespace api