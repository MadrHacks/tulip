import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

import { API_BASE_PATH } from "./const";
import {
  Service,
  FullFlow,
  TickInfo,
  Flow,
  FlowsQuery,
  StatsQuery,
  Stats,
  TicksAttackInfo,
  TicksAttackQuery,
  Shape,
  ShapeTemplate,
  Chain,
  ChainBody,
  Heat,
  ActuatorsStatus,
  ActuatorsAudit,
  Autonomy,
  AttackCandidate,
} from "./types";

function base64DecodeUnicode(str: string) : string {
  const text = atob(str);
  const bytes = new Uint8Array(text.length);
  for(let i = 0; i < text.length; i++)
    bytes[i] = text.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// decodeRank scores a representation kind as [decrypted-root, converter-depth].
// Tulip layers representations as a base kind ("raw"/"decrypted") plus converter
// chains named "<parent> -> <converter>"; a deeper chain is more decoded.
function decodeRank(kind: string): [number, number] {
  const root = kind.startsWith("decrypted") ? 1 : 0;
  const depth = (kind.match(/ -> /g) || []).length;
  return [root, depth];
}

// mostDecodedFirst sorts kinds so the most-decoded (upmost) layer comes first.
// Shared rule with minecore's backend topmost selection.
function mostDecodedFirst(a: string, b: string): number {
  const ra = decodeRank(a);
  const rb = decodeRank(b);
  if (ra[0] !== rb[0]) return rb[0] - ra[0];
  if (ra[1] !== rb[1]) return rb[1] - ra[1];
  return a < b ? 1 : a > b ? -1 : 0;
}

export const tulipApi = createApi({
  baseQuery: fetchBaseQuery({ baseUrl: API_BASE_PATH }),
  endpoints: (builder) => ({
    getServices: builder.query<Service[], void>({
      query: () => "/services",
    }),
    getFlagRegex: builder.query<string, void>({
      query: () => "/flag_regex",
    }),
    getFlow: builder.query<FullFlow, string>({
      query: (id) => `/flow/${id}`,
      transformResponse: (flow: any): FullFlow => {
        const representations: any = {};

        for(const item of flow.items) {
          if(!(item.kind in representations))
            representations[item.kind] = { type: item.kind, flow: [] };
          representations[item.kind].flow.push({
            from: item.direction,
            data: base64DecodeUnicode(item.data),
            b64: item.data,
            time: new Date(item.time).getTime(),
          });
        }

        // Order representations most-decoded first, so index 0 (the default
        // view) is the upmost layer: the deepest converter chain, decrypted root
        // preferred. Mirrors minecore's topmost rule so the UI shows what the
        // analyzer actually reasons over.
        const orderedReprs = (Object.values(representations) as any[]).sort(
          (a, b) => mostDecodedFirst(a.type, b.type)
        );

        return {
          id: flow.id,
          src_port: flow.port_src,
          dst_port: flow.port_dst,
          src_ip: flow.ip_src,
          dst_ip: flow.ip_dst,
          time: new Date(flow.time).getTime(),
          duration: +(flow.duration * 1000).toFixed(0),
          num_packets: flow.packets_count,
          parent_id: flow.link_parent_id,
          child_id: flow.link_child_id,
          tags: flow.tags,
          flags: flow.flags,
          flagids: flow.flagids,
          fuzzyhash: flow.fuzzyhash,
          similarity: flow.similarity,
          filename: flow.pcap_name,
          service_tag: "",
          suricata: [],
          signatures: flow.signatures,
          flow: orderedReprs,
        };
      },
    }),
    getFlows: builder.query<Flow[], FlowsQuery>({
      query: (query) => ({
        url: `/query`,
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: query,
      }),
      transformResponse: (response: Array<any>) => {
        return response.map((flow: any): Flow => ({
          id: flow.id,
          src_port: flow.port_src,
          dst_port: flow.port_dst,
          src_ip: flow.ip_src,
          dst_ip: flow.ip_dst,
          time: new Date(flow.time).getTime(),
          duration: +(flow.duration * 1000).toFixed(0),
          num_packets: flow.packets_count,
          parent_id: flow.link_parent_id,
          child_id: flow.link_child_id,
          tags: flow.tags,
          flags: flow.flags,
          flagids: flow.flagids,
          fuzzyhash: flow.fuzzyhash,
          similarity: flow.similarity,
          filename: flow.pcap_name,
          service_tag: "",
          suricata: [],
        }));
      },
    }),
    getStats: builder.query<Stats[], StatsQuery>({
      query: (query) => ({
        url: `/stats`,
        method: "GET",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        params: {
          service: query.service,
          tick_from: query.tick_from,
          tick_to: query.tick_to,
        }
      })
    }),
    getTags: builder.query<string[], void>({
      query: () => `/tags`,
    }),
    getTickInfo: builder.query<TickInfo, void>({
      query: () => `/tick_info`,
    }),
    getUnderAttack: builder.query<TicksAttackInfo, TicksAttackQuery>({
      query: (query) => ({
        url: '/under_attack',
        params: {
          from_tick: query.from_tick,
          to_tick: query.to_tick,
        }
      }),
    }),
    toPwnTools: builder.query<string, { id: string; kind: string }>({
      query: ({ id, kind }) => ({
        url: `/to_pwn/${id}?kind=${encodeURIComponent(kind)}`,
        responseHandler: "text",
      }),
    }),
    toSinglePythonRequest: builder.query<
      string,
      { body: string; id: string; item_index: number; tokenize: boolean; kind: string }
    >({
      query: ({ body, id, item_index, tokenize, kind }) => ({
        url: `/to_single_python_request?tokenize=${
          tokenize ? "1" : "0"
        }&id=${id}&index=${item_index}&kind=${encodeURIComponent(kind)}`,
        method: "POST",
        responseHandler: "text",
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
        },
        body,
      }),
    }),
    toFullPythonRequest: builder.query<string, { id: string; kind: string }>({
      query: ({ id, kind }) => ({
        url: `/to_python_request/${id}?kind=${encodeURIComponent(kind)}`,
        responseHandler: "text",
      }),
    }),
    starFlow: builder.mutation<unknown, { id: string; star: boolean }>({
      query: ({ id, star }) => ({
        url: `/star`,
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: { id, star },
      }),
      // TODO: optimistic cache update

      // async onQueryStarted({ id, star }, { dispatch, queryFulfilled }) {
      //   // `updateQueryData` requires the endpoint name and cache key arguments,
      //   // so it knows which piece of cache state to update
      //   const patchResult = dispatch(
      //     tulipApi.util.updateQueryData("getFlows", undefined, (flows) => {
      //       // The `flows` is Immer-wrapped and can be "mutated" like in createSlice
      //       const flow = flows.find((flow) => flow._id.$oid === id);
      //       if (flow) {
      //         if (star) {
      //           flow.tags.push("starred");
      //         } else {
      //           flow.tags = flow.tags.filter((tag) => tag != "starred");
      //         }
      //       }
      //     })
      //   );
      //   try {
      //     await queryFulfilled;
      //   } catch {
      //     patchResult.undo();
      //   }
      // },
    }),
    getShapes: builder.query<Shape[], void>({
      query: () => "/shapes",
    }),
    getTemplates: builder.query<ShapeTemplate[], void>({
      query: () => "/templates",
    }),
    getTemplateScaffold: builder.query<string, { service: string; shapeId: number }>({
      query: ({ service, shapeId }) => ({
        url: `/template_scaffold/${service}/${shapeId}`,
        responseHandler: "text",
      }),
    }),
    getChains: builder.query<Chain[], void>({
      query: () => "/chains",
    }),
    getHeat: builder.query<Record<string, Heat>, void>({
      query: () => "/heat",
    }),
    getActuatorsStatus: builder.query<ActuatorsStatus, void>({
      query: () => "/actuators/status",
    }),
    getActuatorsAudit: builder.query<ActuatorsAudit, void>({
      query: () => "/actuators/audit",
    }),
    actuatorControl: builder.mutation<
      unknown,
      { which: string; action: "arm" | "disarm" | "auto_arm" | "auto_disarm" }
    >({
      query: ({ which, action }) => ({
        url: `/actuators/${which}/${action}`,
        method: "POST",
      }),
    }),
    getAutonomy: builder.query<Autonomy, void>({
      query: () => "/autonomy",
    }),
    getCandidates: builder.query<AttackCandidate[], void>({
      query: () => "/candidates",
    }),
    getChainBody: builder.query<ChainBody, number>({
      query: (chainId) => `/chain/${chainId}`,
    }),
    flowTag: builder.mutation<unknown, { id: string; tag: string; apply: boolean }>({
      query: ({ id, tag, apply }) => ({
        url: "/flow_tag",
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: { id, tag, apply },
      }),
    }),
    flowsTagBulk: builder.mutation<{ count: number }, { query: FlowsQuery; tag: string; apply: boolean }>({
      query: ({ query, tag, apply }) => ({
        url: "/flows_tag_bulk",
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: { query, tag, apply },
      }),
    }),
  }),
});

export const {
  useGetServicesQuery,
  useGetFlagRegexQuery,
  useGetFlowQuery,
  useGetFlowsQuery,
  useLazyGetFlowsQuery,
  useGetTagsQuery,
  useGetTickInfoQuery,
  useLazyToPwnToolsQuery,
  useLazyToFullPythonRequestQuery,
  useToSinglePythonRequestQuery,
  useStarFlowMutation,
  useGetStatsQuery,
  useGetUnderAttackQuery,
  useGetShapesQuery,
  useGetTemplatesQuery,
  useLazyGetTemplateScaffoldQuery,
  useGetChainsQuery,
  useGetChainBodyQuery,
  useGetHeatQuery,
  useGetActuatorsStatusQuery,
  useGetActuatorsAuditQuery,
  useActuatorControlMutation,
  useGetAutonomyQuery,
  useGetCandidatesQuery,
  useFlowTagMutation,
  useFlowsTagBulkMutation,
} = tulipApi;
