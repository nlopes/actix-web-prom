/*!
Prometheus instrumentation for actix-web.

By default two metrics are tracked (this assumes the namespace `actix_web_prom`):

  - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total number
   of HTTP requests handled by the actix HttpServer.

  - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method, status): the
   request duration for all HTTP requests handled by the actix HttpServer.


# Usage

First add `actix_web_prom` to your `Cargo.toml`:

```toml
[dependencies]
actix_web_prom = "0.1"
```

You then instantiate the prometheus middleware and pass it to `.wrap()`:

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetrics;

fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetrics::new("api", "/metrics");
    # if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run();
    # }
    Ok(())
}
```

Using the above as an example, a few things are worth mentioning:
 - `api` is the metrics namespace
 - `/metrics` will be auto exposed (GET requests only)

A call to the /metrics endpoint will expose your metrics:

```shell
$ curl http://localhost:8080/metrics
# HELP api_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE api_http_requests_duration_seconds histogram
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.005"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.01"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.025"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.05"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.25"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="0.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="2.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="10"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",method="GET",status="200",le="+Inf"} 1
api_http_requests_duration_seconds_sum{endpoint="/metrics",method="GET",status="200"} 0.00003
api_http_requests_duration_seconds_count{endpoint="/metrics",method="GET",status="200"} 1
# HELP api_http_requests_total Total number of HTTP requests
# TYPE api_http_requests_total counter
api_http_requests_total{endpoint="/metrics",method="GET",status="200"} 1
```

## Custom metrics

You instantiate `PrometheusMetrics` and then use its `.registry` to register your custom
metric (in this case, we use a `IntCounterVec`.

Then you can pass this counter through `.data()` to have it available within the resource
responder.

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetrics;
use prometheus::{opts, IntCounterVec};

fn health(counter: web::Data<IntCounterVec>) -> HttpResponse {
    counter.with_label_values(&["endpoint", "method", "status"]).inc();
    HttpResponse::Ok().finish()
}

fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetrics::new("api", "/metrics");

    let counter_opts = opts!("counter", "some random counter").namespace("api");
    let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();
    prometheus
        .registry
        .register(Box::new(counter.clone()))
        .unwrap();

    # if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .data(counter.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run();
    # }
    Ok(())
}
```

*/
#![deny(missing_docs)]

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::SystemTime;

use actix_service::{Service, Transform};
use actix_web::{
    dev::{Body, BodySize, MessageBody, ResponseBody, ServiceRequest, ServiceResponse},
    http::{Method, StatusCode},
    web::Bytes,
    Error,
};
use futures::future::{ok, FutureResult};
use futures::{Async, Future, Poll};
use prometheus::{opts, Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder};

#[derive(Clone)]
#[must_use = "must be set up as middleware for actix-web"]
/// By default two metrics are tracked (this assumes the namespace `actix_web_prom`):
///
///   - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total
///   number of HTTP requests handled by the actix HttpServer.
///
///   - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method,
///    status): the request duration for all HTTP requests handled by the actix
///    HttpServer.
pub struct PrometheusMetrics {
    pub(crate) http_requests_total: IntCounterVec,
    pub(crate) http_requests_duration_seconds: HistogramVec,

    /// exposed registry for custom prometheus metrics
    pub registry: Registry,
    pub(crate) namespace: String,
    pub(crate) endpoint: String,
}

impl PrometheusMetrics {
    /// Create a new PrometheusMetrics. You set the namespace and the metrics endpoint
    /// through here.
    pub fn new(namespace: &str, endpoint: &str) -> Self {
        let registry = Registry::new();

        let http_requests_total_opts =
            opts!("http_requests_total", "Total number of HTTP requests").namespace(namespace);
        let http_requests_total =
            IntCounterVec::new(http_requests_total_opts, &["endpoint", "method", "status"])
                .unwrap();
        registry
            .register(Box::new(http_requests_total.clone()))
            .unwrap();

        let http_requests_duration_seconds_opts = opts!(
            "http_requests_duration_seconds",
            "HTTP request duration in seconds for all requests"
        )
        .namespace(namespace);
        let http_requests_duration_seconds = HistogramVec::new(
            http_requests_duration_seconds_opts.into(),
            &["endpoint", "method", "status"],
        )
        .unwrap();
        registry
            .register(Box::new(http_requests_duration_seconds.clone()))
            .unwrap();

        PrometheusMetrics {
            http_requests_total,
            http_requests_duration_seconds,
            registry,
            namespace: namespace.to_string(),
            endpoint: endpoint.to_string(),
        }
    }

    fn metrics(&self) -> String {
        let mut buffer = vec![];
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    fn matches(&self, path: &str, method: &Method) -> bool {
        self.endpoint == path && method == Method::GET
    }

    fn update_metrics(&self, path: &str, method: &Method, status: StatusCode, clock: SystemTime) {
        let method = method.to_string();
        let status = status.as_u16().to_string();

        if let Ok(elapsed) = clock.elapsed() {
            let duration =
                (elapsed.as_secs() as f64) + f64::from(elapsed.subsec_nanos()) / 1_000_000_000_f64;
            self.http_requests_duration_seconds
                .with_label_values(&[&path, &method, &status])
                .observe(duration);
        }
        self.http_requests_total
            .with_label_values(&[&path, &method, &status])
            .inc();
    }
}

impl<S, B> Transform<S> for PrometheusMetrics
where
    B: MessageBody,
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<StreamLog<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = PrometheusMetricsMiddleware<S>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PrometheusMetricsMiddleware {
            service,
            inner: Arc::new(self.clone()),
        })
    }
}

#[doc(hidden)]
/// Middleware service for PrometheusMetrics
pub struct PrometheusMetricsMiddleware<S> {
    service: S,
    inner: Arc<PrometheusMetrics>,
}

impl<S, B> Service for PrometheusMetricsMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<StreamLog<B>>;
    type Error = S::Error;
    type Future = MetricsResponse<S, B>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        self.service.poll_ready()
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        MetricsResponse {
            fut: self.service.call(req),
            clock: SystemTime::now(),
            inner: self.inner.clone(),
            _t: PhantomData,
        }
    }
}

#[doc(hidden)]
pub struct MetricsResponse<S, B>
where
    B: MessageBody,
    S: Service,
{
    fut: S::Future,
    clock: SystemTime,
    inner: Arc<PrometheusMetrics>,
    _t: PhantomData<(B,)>,
}

impl<S, B> Future for MetricsResponse<S, B>
where
    B: MessageBody,
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Item = ServiceResponse<StreamLog<B>>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let res = futures::try_ready!(self.fut.poll());

        let req = res.request();
        let inner = self.inner.clone();
        let method = req.method().clone();
        let path = req.path().to_string();

        Ok(Async::Ready(res.map_body(move |mut head, mut body| {
            // We short circuit the response status and body to serve the endpoint
            // automagically. This way the user does not need to set the middleware *AND*
            // an endpoint to serve middleware results. The user is only required to set
            // the middleware and tell us what the endpoint should be.
            if inner.matches(&path, &method) {
                head.status = StatusCode::OK;
                body = ResponseBody::Other(Body::from_message(inner.metrics()));
            }
            ResponseBody::Body(StreamLog {
                body,
                size: 0,
                clock: self.clock,
                inner,
                status: head.status,
                path,
                method,
            })
        })))
    }
}

#[doc(hidden)]
pub struct StreamLog<B> {
    body: ResponseBody<B>,
    size: usize,
    clock: SystemTime,
    inner: Arc<PrometheusMetrics>,
    status: StatusCode,
    path: String,
    method: Method,
}

impl<B> Drop for StreamLog<B> {
    fn drop(&mut self) {
        // update the metrics for this request at the very end of responding
        self.inner
            .update_metrics(&self.path, &self.method, self.status, self.clock);
    }
}

impl<B: MessageBody> MessageBody for StreamLog<B> {
    fn size(&self) -> BodySize {
        self.body.size()
    }

    fn poll_next(&mut self) -> Poll<Option<Bytes>, Error> {
        match self.body.poll_next()? {
            Async::Ready(Some(chunk)) => {
                self.size += chunk.len();
                Ok(Async::Ready(Some(chunk)))
            }
            val => Ok(val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::{call_service, init_service, read_body, read_response, TestRequest};
    use actix_web::{web, App, HttpResponse};

    #[test]
    fn middleware_basic() {
        let prometheus = PrometheusMetrics::new("actix_web_prom", "/metrics");

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(|| HttpResponse::Ok())),
        );

        let res = call_service(
            &mut app,
            TestRequest::with_uri("/health_check").to_request(),
        );
        assert!(res.status().is_success());
        assert_eq!(read_body(res), "");

        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request());
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/health_check\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_check\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[test]
    fn middleware_basic_failure() {
        let prometheus = PrometheusMetrics::new("actix_web_prom", "/prometheus");

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(|| HttpResponse::Ok())),
        );

        call_service(
            &mut app,
            TestRequest::with_uri("/health_checkz").to_request(),
        );
        let res = read_response(&mut app, TestRequest::with_uri("/prometheus").to_request());
        assert!(String::from_utf8(res.to_vec()).unwrap().contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_checkz\",method=\"GET\",status=\"404\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[test]
    fn middleware_custom_counter() {
        let counter_opts = opts!("counter", "some random counter").namespace("actix_web_prom");
        let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();

        let prometheus = PrometheusMetrics::new("actix_web_prom", "/metrics");
        prometheus
            .registry
            .register(Box::new(counter.clone()))
            .unwrap();

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(|| HttpResponse::Ok())),
        );

        // Verify that 'counter' does not appear in the output before we use it
        call_service(
            &mut app,
            TestRequest::with_uri("/health_check").to_request(),
        );
        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request());
        assert!(!String::from_utf8(res.to_vec()).unwrap().contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_counter some random counter
# TYPE actix_web_prom_counter counter
actix_web_prom_counter{endpoint=\"endpoint\",method=\"method\",status=\"status\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));

        // Verify that 'counter' appears after we use it
        counter
            .with_label_values(&["endpoint", "method", "status"])
            .inc();
        counter
            .with_label_values(&["endpoint", "method", "status"])
            .inc();
        call_service(&mut app, TestRequest::with_uri("/metrics").to_request());
        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request());
        assert!(String::from_utf8(res.to_vec()).unwrap().contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_counter some random counter
# TYPE actix_web_prom_counter counter
actix_web_prom_counter{endpoint=\"endpoint\",method=\"method\",status=\"status\"} 2
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }
}
