# GritScan frontend image: Veloasm console + Tailwind, built by Trunk.
# Self-contained (crates.io deps only): build context is ./frontend.
ARG TRUNK_VERSION=0.21.14
# Backend URL baked into the WASM bundle (the page calls it from the browser).
ARG GRITSCAN_API_URL=http://127.0.0.1:8050
FROM rust:1-bookworm AS builder
ARG TRUNK_VERSION
ARG GRITSCAN_API_URL
RUN rustup target add wasm32-unknown-unknown \
    && curl -sSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
        | tar -xz -C /usr/local/bin trunk
WORKDIR /src/frontend
COPY . ./
RUN sed -i 's|pub const BASE_URL: &str = "[^"]*";|pub const BASE_URL: \&str = "'"${GRITSCAN_API_URL}"'";|' src/api.rs \
    && grep -n 'pub const BASE_URL' src/api.rs \
    && trunk build --release

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /src/frontend/dist/ /usr/share/nginx/html/
EXPOSE 80
