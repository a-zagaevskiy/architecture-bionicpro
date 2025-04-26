#pragma once

#include "key_cloack_auth.hpp"

#include <userver/formats/yaml/serialize.hpp>
#include <userver/server/middlewares/configuration.hpp>
#include <userver/server/middlewares/http_middleware_base.hpp>
#include <userver/server/http/http_response.hpp>
#include <userver/server/http/http_status.hpp>

namespace api {

using namespace userver;

class AuthCheckMiddleware final : public server::middlewares::HttpMiddlewareBase {
  std::vector<std::string> allowed_roles_;
  KeycloakAuthComponent& keycloak_;
 public:
  static constexpr std::string_view kName = "auth-check-middleware";

  AuthCheckMiddleware(const server::handlers::HttpHandlerBase&,
                      yaml_config::YamlConfig config,
                      KeycloakAuthComponent& keycloak)
      : allowed_roles_(
            config["allowed_roles"].As<std::vector<std::string>>(false)),
        keycloak_(keycloak) {}

 private:
  void HandleRequest(server::http::HttpRequest& request,
                     server::request::RequestContext& context) const override {
    auto& response = request.GetHttpResponse();
    std::string authToken = request.GetHeader(kAuthorization);
    if (authToken.empty() || authToken.find("Bearer ") == std::string::npos) {
      std::cerr << "Empty or incorrect token\n";
      response.SetStatus(server::http::HttpStatus::kUnauthorized);
      return;
    }

    // Remove "Bearer " from token
    authToken = authToken.substr(7);

    // Validate token
    formats::json::Value json;
    try {
      json = keycloak_.VerifyToken(authToken);
    } catch (const std::exception& e) {
      response.SetStatus(server::http::HttpStatus::kUnauthorized);
      return;
    }

    if (json.IsEmpty()) {
        response.SetStatus(server::http::HttpStatus::kUnauthorized);
        return;
    }

    //  Check user roles
    auto roles = json["realm_access"]["roles"].As<std::vector<std::string>>();
    if (std::none_of(roles.begin(), roles.end(), [&](const std::string& role) {
          return std::any_of(allowed_roles_.begin(), allowed_roles_.end(),
                             [&role](const std::string& allowed_role) {
                               return allowed_role == role;
                             });
        })) {
      response.SetStatus(server::http::HttpStatus::kForbidden);
      return;
    }

    Next(request, context);
  }

  static constexpr http::headers::PredefinedHeader kAuthorization{
      "Authorization"};
};

class AuthCheckMiddlewareFactory final
    : public server::middlewares::HttpMiddlewareFactoryBase {
  KeycloakAuthComponent& keycloak_;

 public:
  static constexpr std::string_view kName{AuthCheckMiddleware::kName};

  AuthCheckMiddlewareFactory(const components::ComponentConfig& config,
                             const components::ComponentContext& context)
      : server::middlewares::HttpMiddlewareFactoryBase(config, context),
        keycloak_(context.FindComponent<api::KeycloakAuthComponent>()) {}

 private:
  std::unique_ptr<server::middlewares::HttpMiddlewareBase> Create(
      const server::handlers::HttpHandlerBase& handler,
      yaml_config::YamlConfig middleware_config) const override {
    return std::make_unique<AuthCheckMiddleware>(
        handler, std::move(middleware_config), keycloak_);
  }

  yaml_config::Schema GetMiddlewareConfigSchema() const override {
    return formats::yaml::FromString(R"(
type: object
description: auth middleware component
additionalProperties: false
properties:
    allowed_roles:
        type: array
        description: allowed roles
        items:
            type: string
            description: role name
)")
        .As<yaml_config::Schema>();
  }
};

}  // namespace api