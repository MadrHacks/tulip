FROM timescale/timescaledb:latest-pg15 AS builder

RUN apk add --no-cache build-base git

COPY tulip /tulip
RUN make -C /tulip USE_PGXS=1 with_llvm=no install DESTDIR=/out

RUN git clone --depth 1 --branch PG15 https://github.com/ossc-db/pg_hint_plan /pg_hint_plan && \
	make -C /pg_hint_plan USE_PGXS=1 with_llvm=no install DESTDIR=/out

FROM timescale/timescaledb:latest-pg15

COPY --from=builder /out/ /
