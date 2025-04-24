#include <userver/components/minimal_server_component_list.hpp>
#include <userver/utils/daemon_run.hpp>
#include "cors_middleware.hpp"
#include "reports_handler.hpp"

int main(int argc, char *argv[]) {
  const auto component_list = userver::components::MinimalServerComponentList()
                                  .Append<api::CorsMiddleware>()
                                  .Append<api::ReportHandler>();

  return userver::utils::DaemonMain(argc, argv, component_list);
}