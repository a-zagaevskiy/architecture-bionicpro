#include <userver/components/component.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/server/http/http_response.hpp>
#include <userver/yaml_config/schema.hpp>

namespace api {

using namespace userver;

class CorsMiddleware final : public userver::server::handlers::HttpHandlerBase {
  std::vector<std::string> allowed_origins_;
  bool allow_credentials_;

 public:
  static constexpr std::string_view kName = "cors-middleware";

  using HttpHandlerBase::HttpHandlerBase;

  CorsMiddleware(const components::ComponentConfig& config,
                 const components::ComponentContext& context)
      : HttpHandlerBase(config, context),
        allowed_origins_(
            config["allowed_origins"].As<std::vector<std::string>>()),
        allow_credentials_(config["allow_credentials"].As<bool>(false)) {}

  std::string HandleRequestThrow(
      const userver::server::http::HttpRequest& request,
      userver::server::request::RequestContext& context) const override {
    auto& response = request.GetHttpResponse();
    const auto& origin = request.GetHeader(std::string("Origin"));

    if (!origin.empty() &&
        std::find(allowed_origins_.begin(), allowed_origins_.end(), origin) !=
            allowed_origins_.end()) {
      response.SetHeader(std::string("Access-Control-Allow-Origin"), origin);
    }

    response.SetHeader(std::string("Access-Control-Allow-Methods"),
                       std::string("GET, POST, PUT, DELETE, OPTIONS"));
    response.SetHeader(std::string("Access-Control-Allow-Headers"),
                       std::string("Content-Type, Authorization"));

    if (allow_credentials_) {
      response.SetHeader(std::string("Access-Control-Allow-Credentials"),
                         std::string("true"));
    }

    if (request.GetMethod() == userver::server::http::HttpMethod::kOptions) {
      response.SetStatus(userver::server::http::HttpStatus::kNoContent);
      return {};
    }
    return HttpHandlerBase::HandleRequestThrow(request, context);
  }

  static yaml_config::Schema GetStaticConfigSchema() {
    return yaml_config::Schema(R"(
type: object
description: CORS middleware component
additionalProperties: false
properties:
    allow_credentials:
        type: boolean
        description: whether to allow credentials
        default: false
    allowed_origins:
        type: array
        items:
            type: string
        description: list of allowed origins
        default: []
)");
  }
};

}  // namespace api