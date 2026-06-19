FROM timescale/timescaledb:latest-pg15 AS builder

RUN apk add --no-cache build-base git

COPY tulip /tulip
RUN make -C /tulip USE_PGXS=1 with_llvm=no install DESTDIR=/out

RUN git clone --depth 1 --branch PG15 https://github.com/ossc-db/pg_hint_plan /pg_hint_plan && \
	make -C /pg_hint_plan USE_PGXS=1 with_llvm=no install DESTDIR=/out

FROM timescale/timescaledb:latest-pg15

COPY --from=builder /out/ /

# Bake the DB init schema so the image is self-contained (no runtime mount).
# Numeric prefixes preserve the apply order in /docker-entrypoint-initdb.d.
COPY schema/system.sql    /docker-entrypoint-initdb.d/100_system.sql
COPY schema/functions.sql /docker-entrypoint-initdb.d/101_functions.sql
COPY schema/schema.sql    /docker-entrypoint-initdb.d/102_schema.sql
