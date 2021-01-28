/*!
Prometheus instrumentation for [actix-web](https://github.com/actix/actix-web). This middleware is heavily influenced by the work in [sd2k/rocket_prometheus](https://github.com/sd2k/rocket_prometheus). We track the same default metrics and allow for adding user defined metrics.

By default two metrics are tracked (this assumes the namespace `actix_web_prom`):

  - `actix_web_prom_http_requests_total` (labels: endpoint, method, status): the total number
   of HTTP requests handled by the actix HttpServer.

  - `actix_web_prom_http_requests_duration_seconds` (labels: endpoint, method, status): the
   request duration for all HTTP requests handled by the actix HttpServer.


# Usage

First add `actix-web-prom` to your `Cargo.toml`:

```toml
[dependencies]
actix-web-prom = "0.5"
```

You then instantiate the prometheus middleware and pass it to `.wrap()`:

```rust
use std::collections::HashMap;

use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetrics;

fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut labels = HashMap::new();
    labels.insert("label1".to_string(), "value1".to_string());
    let prometheus = PrometheusMetrics::new("api", Some("/metrics"), Some(labels));
    # if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
    # }
    Ok(())
}
```

Using the above as an example, a few things are worth mentioning:
 - `api` is the metrics namespace
 - `/metrics` will be auto exposed (GET requests only) with Content-Type header `content-type: text/plain; version=0.0.4; charset=utf-8`
 - `Some(labels)` is used to add fixed labels to the metrics; `None` can be passed instead
  if no additional labels are necessary.


A call to the /metrics endpoint will expose your metrics:

```shell
$ curl http://localhost:8080/metrics
# HELP api_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE api_http_requests_duration_seconds histogram
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.005"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.01"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.025"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.05"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.25"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="0.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="1"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="2.5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="5"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="10"} 1
api_http_requests_duration_seconds_bucket{endpoint="/metrics",label1="value1",method="GET",status="200",le="+Inf"} 1
api_http_requests_duration_seconds_sum{endpoint="/metrics",label1="value1",method="GET",status="200"} 0.00003
api_http_requests_duration_seconds_count{endpoint="/metrics",label1="value1",method="GET",status="200"} 1
# HELP api_http_requests_total Total number of HTTP requests
# TYPE api_http_requests_total counter
api_http_requests_total{endpoint="/metrics",label1="value1",method="GET",status="200"} 1
```

## Custom metrics

You instantiate `PrometheusMetrics` and then use its `.registry` to register your custom
metric (in this case, we use a `IntCounterVec`).

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetrics::new("api", Some("/metrics"), None);

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
        .run()
        .await?;
    # }
    Ok(())
}
```

## Custom `Registry`

Some apps might have more than one `actix_web::HttpServer`.
If that's the case, you might want to use your own registry:

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prom::PrometheusMetrics;
use actix_web::rt::System;
use prometheus::Registry;
use std::thread;

fn public_handler() -> HttpResponse {
    HttpResponse::Ok().body("Everyone can see it!")
}

fn private_handler() -> HttpResponse {
    HttpResponse::Ok().body("This can be hidden behind a firewall")
}

fn main() -> std::io::Result<()> {
    let shared_registry = Registry::new();

    let private_metrics = PrometheusMetrics::new_with_registry(
                                        shared_registry.clone(),
                                        "private_api",
                                        Some("/metrics"),
                                        None,
                                    )
                                    // It is safe to unwrap when __no other app has the same namespace__
                                    .unwrap();
    let public_metrics = PrometheusMetrics::new_with_registry(
                                        shared_registry.clone(),
                                        "public_api",
                                        // Metrics should not be available from the outside
                                        None,
                                        None,
                                    )
                                    .unwrap();

# if false {
    let private_thread = thread::spawn(move || {
        let mut sys = System::new("private");
        let srv = HttpServer::new(move || {
            App::new()
                .wrap(private_metrics.clone())
                .service(web::resource("/test").to(private_handler))
        })
        .bind("127.0.0.1:8081")
        .unwrap()
        .run();
        sys.block_on(srv).unwrap();
    });

    let public_thread = thread::spawn(|| {
        let mut sys = System::new("public");
        let srv = HttpServer::new(move || {
            App::new()
                .wrap(public_metrics.clone())
                .service(web::resource("/test").to(public_handler))
        })
        .bind("127.0.0.1:8082")
        .unwrap()
        .run();
        sys.block_on(srv).unwrap();
    });

    private_thread.join().unwrap();
    public_thread.join().unwrap();
# }
    Ok(())
}

```

*/
#![deny(missing_docs)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use actix_http::http::{header::CONTENT_TYPE, HeaderValue};
use actix_service::{Service, Transform};
use actix_web::{
    dev::{Body, BodySize, MessageBody, ResponseBody, ServiceRequest, ServiceResponse},
    http::{Method, StatusCode},
    web::Bytes,
    Error,
};
use futures::{
    future::{ok, Ready},
    task::{Context, Poll},
    Future,
};
use prometheus::{Encoder, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};

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
    pub(crate) endpoint: Option<String>,
    pub(crate) const_labels: HashMap<String, String>,
}

impl PrometheusMetrics {
    /// Create a new PrometheusMetrics. You set the namespace and the metrics endpoint
    /// through here.
    pub fn new(
        namespace: &str,
        endpoint: Option<&str>,
        const_labels: Option<HashMap<String, String>>,
    ) -> Self {
        let registry = Registry::new();

        // this should not error because we are creating new registry
        PrometheusMetrics::new_with_registry(registry, namespace, endpoint, const_labels).unwrap()
    }

    /// Create a new PrometheusMetrics.
    /// Throws error if "<`namespace`>_http_requests_total" already registered
    pub fn new_with_registry(
        registry: Registry,
        namespace: &str,
        endpoint: Option<&str>,
        const_labels: Option<HashMap<String, String>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let labels_hashmap = const_labels.map_or(HashMap::new(), |h| h);
        let http_requests_total_opts =
            Opts::new("http_requests_total", "Total number of HTTP requests")
                .namespace(namespace)
                .const_labels(labels_hashmap.clone());
        let http_requests_total =
            IntCounterVec::new(http_requests_total_opts, &["endpoint", "method", "status"])
                .unwrap();
        registry
            .register(Box::new(http_requests_total.clone()))
            .unwrap();

        let http_requests_duration_seconds_opts = Opts::new(
            "http_requests_duration_seconds",
            "HTTP request duration in seconds for all requests",
        )
        .namespace(namespace)
        .const_labels(labels_hashmap.clone());

        let http_requests_duration_seconds = HistogramVec::new(
            http_requests_duration_seconds_opts.into(),
            &["endpoint", "method", "status"],
        )
        .unwrap();
        registry.register(Box::new(http_requests_duration_seconds.clone()))?;

        Ok(PrometheusMetrics {
            http_requests_total,
            http_requests_duration_seconds,
            registry,
            namespace: namespace.to_string(),
            endpoint: endpoint.map(|e| e.to_string()),
            const_labels: labels_hashmap,
        })
    }

    fn metrics(&self) -> String {
        let mut buffer = vec![];
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    fn matches(&self, path: &str, method: &Method) -> bool {
        if self.endpoint.is_some() {
            self.endpoint.as_ref().unwrap() == path && method == Method::GET
        } else {
            false
        }
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

impl<S, B> Transform<S, ServiceRequest> for PrometheusMetrics
where
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Response = ServiceResponse<StreamLog<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = PrometheusMetricsMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PrometheusMetricsMiddleware {
            service,
            inner: Arc::new(self.clone()),
        })
    }
}

#[doc(hidden)]
#[pin_project::pin_project]
pub struct LoggerResponse<S, B>
where
    B: MessageBody,
    S: Service<ServiceRequest>,
{
    #[pin]
    fut: S::Future,
    time: SystemTime,
    inner: Arc<PrometheusMetrics>,
    _t: PhantomData<(B,)>,
}

impl<S, B> Future for LoggerResponse<S, B>
where
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Output = Result<ServiceResponse<StreamLog<B>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let res = match futures::ready!(this.fut.poll(cx)) {
            Ok(res) => res,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let time = *this.time;
        let req = res.request();
        let method = req.method().clone();
        let pattern_or_path = req
            .match_pattern()
            .unwrap_or_else(|| req.path().to_string());
        let path = req.path().to_string();
        let inner = this.inner.clone();

        Poll::Ready(Ok(res.map_body(move |mut head, mut body| {
            // We short circuit the response status and body to serve the endpoint
            // automagically. This way the user does not need to set the middleware *AND*
            // an endpoint to serve middleware results. The user is only required to set
            // the middleware and tell us what the endpoint should be.
            if inner.matches(&path, &method) {
                head.status = StatusCode::OK;
                head.headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );
                body = ResponseBody::Other(Body::from_message(inner.metrics()));
            }
            ResponseBody::Body(StreamLog {
                body,
                size: 0,
                clock: time,
                inner,
                status: head.status,
                path: pattern_or_path,
                method,
            })
        })))
    }
}

#[doc(hidden)]
/// Middleware service for PrometheusMetrics
pub struct PrometheusMetricsMiddleware<S> {
    service: S,
    inner: Arc<PrometheusMetrics>,
}

impl<S, B> Service<ServiceRequest> for PrometheusMetricsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = ServiceResponse<StreamLog<B>>;
    type Error = S::Error;
    type Future = LoggerResponse<S, B>;

    fn poll_ready(&mut self, ct: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ct)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        LoggerResponse {
            fut: self.service.call(req),
            time: SystemTime::now(),
            inner: self.inner.clone(),
            _t: PhantomData,
        }
    }
}

use pin_project::{pin_project, pinned_drop};
use std::marker::PhantomData;

#[doc(hidden)]
#[pin_project(PinnedDrop)]
pub struct StreamLog<B> {
    #[pin]
    body: ResponseBody<B>,
    size: usize,
    clock: SystemTime,
    inner: Arc<PrometheusMetrics>,
    status: StatusCode,
    path: String,
    method: Method,
}

#[pinned_drop]
impl<B> PinnedDrop for StreamLog<B> {
    fn drop(self: Pin<&mut Self>) {
        // update the metrics for this request at the very end of responding
        self.inner
            .update_metrics(&self.path, &self.method, self.status, self.clock);
    }
}

impl<B: MessageBody> MessageBody for StreamLog<B> {
    fn size(&self) -> BodySize {
        self.body.size()
    }

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, Error>>> {
        let this = self.project();
        match MessageBody::poll_next(this.body, cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                *this.size += chunk.len();
                Poll::Ready(Some(Ok(chunk)))
            }
            val => val,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::rt as actix_rt;
    use actix_web::test::{call_service, init_service, read_body, read_response, TestRequest};
    use actix_web::{web, App, HttpResponse};

    use prometheus::{Counter, Opts};

    #[actix_rt::test]
    async fn middleware_basic() {
        let prometheus = PrometheusMetrics::new("actix_web_prom", Some("/metrics"), None);

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(
            &mut app,
            TestRequest::with_uri("/health_check").to_request(),
        )
        .await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = call_service(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
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

    #[actix_rt::test]
    async fn middleware_match_pattern() {
        let prometheus = PrometheusMetrics::new("actix_web_prom", Some("/metrics"), None);

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/resource/{id}").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(
            &mut app,
            TestRequest::with_uri("/resource/123").to_request(),
        )
        .await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/resource/{id}\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/resource/{id}\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }

    #[actix_rt::test]
    async fn middleware_metrics_exposed_with_conflicting_pattern() {
        let prometheus = PrometheusMetrics::new("actix_web_prom", Some("/metrics"), None);

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/{path}").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(&mut app, TestRequest::with_uri("/something").to_request()).await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests"
        ).to_vec()).unwrap()));
    }

    #[actix_rt::test]
    async fn middleware_basic_failure() {
        let prometheus = PrometheusMetrics::new("actix_web_prom", Some("/prometheus"), None);

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        call_service(
            &mut app,
            TestRequest::with_uri("/health_checkz").to_request(),
        )
        .await;
        let res = read_response(&mut app, TestRequest::with_uri("/prometheus").to_request()).await;
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

    #[actix_rt::test]
    async fn middleware_custom_counter() {
        let counter_opts = Opts::new("counter", "some random counter").namespace("actix_web_prom");
        let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();

        let prometheus = PrometheusMetrics::new("actix_web_prom", Some("/metrics"), None);
        prometheus
            .registry
            .register(Box::new(counter.clone()))
            .unwrap();

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        // Verify that 'counter' does not appear in the output before we use it
        call_service(
            &mut app,
            TestRequest::with_uri("/health_check").to_request(),
        )
        .await;
        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
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
        call_service(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
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

    #[actix_rt::test]
    async fn middleware_none_endpoint() {
        // Init PrometheusMetrics with none URL
        let prometheus = PrometheusMetrics::new("actix_web_prom", None, None);

        let mut app =
            init_service(App::new().wrap(prometheus.clone()).service(
                web::resource("/metrics").to(|| HttpResponse::Ok().body("not prometheus")),
            ))
            .await;

        let response =
            read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;

        // Assert app works
        assert_eq!(
            String::from_utf8(response.to_vec()).unwrap(),
            "not prometheus"
        );

        // Assert counter counts
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = prometheus.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(output.contains(
            "actix_web_prom_http_requests_total{endpoint=\"/metrics\",method=\"GET\",status=\"200\"} 1"
        ));
    }

    #[actix_rt::test]
    async fn middleware_custom_registry_works() {
        // Init Prometheus Registry
        let registry = Registry::new();

        let counter_opts = Opts::new("test_counter", "test counter help");
        let counter = Counter::with_opts(counter_opts).unwrap();
        registry.register(Box::new(counter.clone())).unwrap();

        counter.inc_by(10_f64);

        // Init PrometheusMetrics
        let prometheus = PrometheusMetrics::new_with_registry(
            registry,
            "actix_web_prom",
            Some("/metrics"),
            None,
        )
        .unwrap();

        let mut app = init_service(
            App::new()
                .wrap(prometheus.clone())
                .service(web::resource("/test").to(|| HttpResponse::Ok().finish())),
        )
        .await;

        // all http counters are 0 because this is the first http request,
        // so we should get only 10 on test counter
        let response =
            read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;

        let ten_test_counter =
            "# HELP test_counter test counter help\n# TYPE test_counter counter\ntest_counter 10\n";
        assert_eq!(
            String::from_utf8(response.to_vec()).unwrap(),
            ten_test_counter
        );

        // all http counters are 1 because this is the second http request,
        // plus 10 on test counter
        let response =
            read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
        let response_string = String::from_utf8(response.to_vec()).unwrap();

        let one_http_counters = "# HELP actix_web_prom_http_requests_total Total number of HTTP requests\n# TYPE actix_web_prom_http_requests_total counter\nactix_web_prom_http_requests_total{endpoint=\"/metrics\",method=\"GET\",status=\"200\"} 1";

        assert!(response_string.contains(ten_test_counter));
        assert!(response_string.contains(one_http_counters));
    }

    #[actix_rt::test]
    async fn middleware_const_labels() {
        let mut labels = HashMap::new();
        labels.insert("label1".to_string(), "value1".to_string());
        labels.insert("label2".to_string(), "value2".to_string());
        let prometheus = PrometheusMetrics::new("actix_web_prom", Some("/metrics"), Some(labels));

        let mut app = init_service(
            App::new()
                .wrap(prometheus)
                .service(web::resource("/health_check").to(HttpResponse::Ok)),
        )
        .await;

        let res = call_service(
            &mut app,
            TestRequest::with_uri("/health_check").to_request(),
        )
        .await;
        assert!(res.status().is_success());
        assert_eq!(read_body(res).await, "");

        let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
        let body = String::from_utf8(res.to_vec()).unwrap();
        assert!(&body.contains(
            &String::from_utf8(web::Bytes::from(
                "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
# TYPE actix_web_prom_http_requests_duration_seconds histogram
actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/health_check\",label1=\"value1\",label2=\"value2\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
"
        ).to_vec()).unwrap()));
        assert!(body.contains(
            &String::from_utf8(
                web::Bytes::from(
                    "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
# TYPE actix_web_prom_http_requests_total counter
actix_web_prom_http_requests_total{endpoint=\"/health_check\",label1=\"value1\",label2=\"value2\",method=\"GET\",status=\"200\"} 1
"
                )
                .to_vec()
            )
            .unwrap()
        ));
    }
}
