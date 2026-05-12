use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use metrics_exporter_prometheus::PrometheusHandle;

use crate::error::AppError;

#[utoipa::path(
    get,
    operation_id = "get_metrics",
    path = "/metrics",
    responses(
        (status = 200, description = "Full y2q metrics")
    ),
    tag = "observability",
)]
pub async fn handle(
    _req: HttpRequest,
    metrics_data: web::Data<PrometheusHandle>,
) -> Result<HttpResponse, AppError> {
    let payload = metrics_data.render();
    let response = HttpResponse::with_body(StatusCode::OK, BoxBody::new(payload));

    Ok(response)
}
