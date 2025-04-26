#include <userver/clients/dns/component.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/utils/daemon_run.hpp>
#include "auth_check_middleware.hpp"
#include "cors_middleware.hpp"
#include "key_cloack_auth.hpp"
#include "reports_handler.hpp"

namespace api
{
using namespace userver;

class CustomPipelineBuilder final
    : public server::middlewares::HandlerPipelineBuilder {
 public:
  using HandlerPipelineBuilder::HandlerPipelineBuilder;

  server::middlewares::MiddlewaresList BuildPipeline(
      server::middlewares::MiddlewaresList server_middleware_pipeline)
      const override {
    auto& pipeline = server_middleware_pipeline;
    pipeline.emplace_back(CorsMiddleware::kName);
    pipeline.emplace_back(AuthCheckMiddleware::kName);
    return pipeline;
  }
};
}

int main(int argc, char *argv[]) {
  const auto component_list =
      userver::components::MinimalServerComponentList()
          .Append<userver::clients::dns::Component>()
          .Append<userver::components::HttpClient>()
          .Append<api::KeycloakAuthComponent>()
          .Append<api::ReportHandler>()
          .Append<api::CustomPipelineBuilder>("custom-middleware-pipeline-builder")
          .Append<api::AuthCheckMiddlewareFactory>()
          .Append<api::CorsMiddlewareFactory>();

  return userver::utils::DaemonMain(argc, argv, component_list);
}