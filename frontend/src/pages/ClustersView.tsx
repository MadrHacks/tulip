import { Fragment, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";
import {
  useGetClustersQuery,
  useGetTemplatesQuery,
  useGetHeatQuery,
  useFlowsTagBulkMutation,
} from "../api";
import { Cluster } from "../types";
import { Tag } from "../components/Tag";

export function ClustersView() {
  const { data: clusters = [] } = useGetClustersQuery();
  const { data: templates = [] } = useGetTemplatesQuery();
  const { data: heat = {} } = useGetHeatQuery();
  const [flowsTagBulk] = useFlowsTagBulkMutation();
  const [labeled, setLabeled] = useState<Record<string, string>>({});
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const templatedTags = useMemo(
    () => new Set(templates.map((t) => t.tag)),
    [templates]
  );

  // Group clusters under their service so the service-level heat (SLA / lost /
  // stolen) is shown once per service instead of being repeated — and misread as
  // per-cluster — on every row. A/D triage order across services: flag loss
  // first, then services we're bleeding on (heat), then raw volume; within a
  // service, the clusters leaking the most flags come first.
  const grouped = useMemo(() => {
    const lost = (service: string) => heat[service]?.our_lost ?? 0;
    const byService = new Map<string, Cluster[]>();
    for (const c of clusters) {
      const arr = byService.get(c.service);
      if (arr) arr.push(c);
      else byService.set(c.service, [c]);
    }
    return [...byService.entries()]
      .map(([service, cs]) => ({
        service,
        flagOut: cs.reduce((sum, c) => sum + c.flag_out, 0),
        clusters: [...cs].sort(
          (a, b) => b.flag_out - a.flag_out || b.count - a.count
        ),
      }))
      .sort(
        (a, b) =>
          b.flagOut - a.flagOut ||
          lost(b.service) - lost(a.service) ||
          a.service.localeCompare(b.service)
      );
  }, [clusters, heat]);

  const openCluster = (tag: string) => {
    dispatch(toggleFilterTag(tag));
    navigate(`/?${searchParams}`);
  };

  const label = (tag: string, verdict: "attack" | "benign") => {
    flowsTagBulk({
      query: { tags_include: [tag] },
      tag: `verdict:${verdict}`,
      apply: true,
    });
    setLabeled((prev) => ({ ...prev, [tag]: verdict }));
  };

  const verdictBtn = (
    tag: string,
    verdict: "attack" | "benign",
    label_: string,
    active: string
  ) => {
    const on = labeled[tag] === verdict;
    return (
      <button
        className={`px-2 py-0.5 rounded text-xs mr-1 ${
          on ? active : "bg-gray-500/15 text-secondary hover:bg-gray-500/30"
        }`}
        onClick={(e) => {
          e.stopPropagation();
          label(tag, verdict);
        }}
      >
        {label_}
      </button>
    );
  };

  return (
    <div className="flex flex-col h-full p-4 bg-main text-app">
      <h1 className="text-2xl font-bold mb-4">Clusters</h1>
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-subtle bg-panel sticky top-0">
              <th className="px-3 py-2 text-left text-secondary font-semibold">Cluster</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Flows</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Flag out</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Flag in</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Template</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Verdict</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Tag</th>
            </tr>
          </thead>
          <tbody>
            {grouped.map((group) => {
              const h = heat[group.service];
              return (
                <Fragment key={group.service}>
                  {/* Service heat shown once for the whole service, not per row. */}
                  <tr className="border-b border-subtle bg-gray-500/10">
                    <td colSpan={7} className="px-3 py-2">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="font-semibold">{group.service}</span>
                        <span className="text-xs text-secondary">
                          {group.clusters.length} cluster{group.clusters.length === 1 ? "" : "s"}
                        </span>
                        {h && (
                          <span
                            className={`text-xs ${
                              h.our_sla_ok
                                ? "text-green-600 dark:text-green-400"
                                : "text-red-600 dark:text-red-400 font-semibold"
                            }`}
                          >
                            SLA {h.our_sla_ok ? "ok" : "down"}
                          </span>
                        )}
                        {h && h.our_lost > 0 && (
                          <span className="text-xs inline-block px-2 py-0.5 rounded bg-orange-500/20 text-orange-600 dark:text-orange-400">
                            {h.our_lost} lost
                          </span>
                        )}
                        {h && h.our_stolen > 0 && (
                          <span className="text-xs inline-block px-2 py-0.5 rounded bg-red-500/20 text-red-600 dark:text-red-400">
                            {h.our_stolen} stolen
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                  {group.clusters.map((cluster) => (
                    <tr
                      key={cluster.tag}
                      className="border-b border-subtle hover:bg-gray-500/10 cursor-pointer"
                      onClick={() => openCluster(cluster.tag)}
                    >
                      <td className="px-3 py-2 font-mono text-xs">{cluster.id}</td>
                      <td className="px-3 py-2 text-center">{cluster.count}</td>
                      <td className="px-3 py-2 text-center">
                        {cluster.flag_out > 0 && (
                          <span className="inline-block px-2 py-0.5 rounded bg-red-500/20 text-red-600 dark:text-red-400">
                            {cluster.flag_out}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center">
                        {cluster.flag_in > 0 && (
                          <span className="inline-block px-2 py-0.5 rounded bg-green-500/20 text-green-600 dark:text-green-400">
                            {cluster.flag_in}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center">
                        {templatedTags.has(cluster.tag) && (
                          <span className="text-blue-600 dark:text-blue-400 font-semibold">✓</span>
                        )}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        {verdictBtn(cluster.tag, "attack", "⚔ Exploit", "bg-red-500/25 text-red-600 dark:text-red-400")}
                        {verdictBtn(cluster.tag, "benign", "✓ Benign", "bg-green-500/25 text-green-600 dark:text-green-400")}
                      </td>
                      <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                        <Tag tag={cluster.tag} />
                      </td>
                    </tr>
                  ))}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
