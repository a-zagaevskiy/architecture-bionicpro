#pragma once

#include <userver/formats/yaml/serialize.hpp>
#include <userver/server/middlewares/configuration.hpp>
#include <userver/server/middlewares/http_middleware_base.hpp>
#include <userver/server/http/http_response.hpp>

namespace api {

using namespace userver;

class CorsMiddleware final : public server::middlewares::HttpMiddlewareBase {
  bool allow_credentials_;

 public:
  static constexpr std::string_view kName = "cors-middleware";

  CorsMiddleware(const server::handlers::HttpHandlerBase&,
                 yaml_config::YamlConfig config)
      : allow_credentials_(config["allow_credentials"].As<bool>(false)) {}

 private:
  void HandleRequest(server::http::HttpRequest& request,
                     server::request::RequestContext& context) const override {

    auto& response = request.GetHttpResponse();
    response.SetHeader(kAccessControlAllowOrigin, std::string{"*"});
    response.SetHeader(kAccessControlAllowMethods, std::string{"*"});
    response.SetHeader(kAccessControlAllowHeaders, std::string{"*"});
    if (allow_credentials_) {
      response.SetHeader(kAccessControlAllowCredentials, std::string("true"));
    }

    if (request.GetMethod() == server::http::HttpMethod::kOptions) {
      response.SetHeader(kAccessControlMaxAge, std::to_string(86400));
      response.SetStatus(server::http::HttpStatus::kOk);
      return;
    }
    Next(request, context);
  }

  static constexpr http::headers::PredefinedHeader kAccessControlAllowOrigin{
      "Access-Control-Allow-Origin"};
  static constexpr http::headers::PredefinedHeader kAccessControlAllowMethods{
      "Access-Control-Allow-Methods"};
  static constexpr http::headers::PredefinedHeader kAccessControlAllowHeaders{
      "Access-Control-Allow-Headers"};
  static constexpr http::headers::PredefinedHeader
      kAccessControlAllowCredentials{"Access-Control-Allow-Credentials"};
  static constexpr http::headers::PredefinedHeader
      kAccessControlMaxAge{"Access-Control-Max-Age"};
};

class CorsMiddlewareFactory final
    : public server::middlewares::HttpMiddlewareFactoryBase {
 public:
  static constexpr std::string_view kName{CorsMiddleware::kName};
 
  using HttpMiddlewareFactoryBase::HttpMiddlewareFactoryBase;
 
 private:
  std::unique_ptr<server::middlewares::HttpMiddlewareBase> Create(
      const server::handlers::HttpHandlerBase& handler,
      yaml_config::YamlConfig middleware_config) const override {
    return std::make_unique<CorsMiddleware>(handler,
                                            std::move(middleware_config));
  }

  yaml_config::Schema GetMiddlewareConfigSchema() const override {
    return formats::yaml::FromString(R"(
type: object
description: CORS middleware component
additionalProperties: false
properties:
    allow_credentials:
        type: boolean
        description: whether to allow credentials
)")
        .As<yaml_config::Schema>();
  }
};

}  // namespace api