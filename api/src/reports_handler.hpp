#include <userver/server/handlers/http_handler_base.hpp>

namespace api {

class ReportHandler final : public userver::server::handlers::HttpHandlerBase {
 public:
  static constexpr std::string_view kName = "handler-reports";

  using HttpHandlerBase::HttpHandlerBase;

  std::string HandleRequestThrow(
      const userver::server::http::HttpRequest &,
      userver::server::request::RequestContext &) const override {
    return "The Answer to the Ultimate Question of Life, the Universe, and "
           "Everything is 42\n";
  }
};

}  // namespace api
