#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/utils/daemon_run.hpp>

namespace api {
class ReportHandler final : public userver::server::handlers::HttpHandlerBase {
 public:
  static constexpr std::string_view kName = "handler-reports";

  using HttpHandlerBase::HttpHandlerBase;

  std::string HandleRequestThrow(
      const userver::server::http::HttpRequest &,
      userver::server::request::RequestContext &) const override {
    return "The Answer to the Ultimate Question of Life, the Universe, and Everything is 42\n";
  }
};

}  // namespace api

int main(int argc, char *argv[]) {
  const auto component_list = userver::components::MinimalServerComponentList()
                                  .Append<api::ReportHandler>();

  return userver::utils::DaemonMain(argc, argv, component_list);
}