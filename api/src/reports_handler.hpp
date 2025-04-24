#include <userver/server/handlers/http_handler_base.hpp>

namespace api {

class ReportHandler final : public userver::server::handlers::HttpHandlerBase {
 public:
  static constexpr std::string_view kName = "handler-reports";

  using HttpHandlerBase::HttpHandlerBase;

  std::string HandleRequestThrow(
      const userver::server::http::HttpRequest& request,
      userver::server::request::RequestContext&) const override {
    auto& response = request.GetHttpResponse();
    response.SetHeader(kContentDisposition, "attachment");
    response.SetContentType("text/plain");
    return "The Answer to the Ultimate Question of Life, the Universe, and "
           "Everything is 42";
  }

  static constexpr http::headers::PredefinedHeader kContentDisposition{
      "Content-Disposition"};
};

}  // namespace api
