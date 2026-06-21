import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";
import { useGetClustersQuery, useGetTemplatesQuery } from "../api";
import { Tag } from "../components/Tag";

export function ClustersView() {
  const { data: clusters = [] } = useGetClustersQuery();
  const { data: templates = [] } = useGetTemplatesQuery();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const templatedTags = useMemo(
    () => new Set(templates.map((t) => t.tag)),
    [templates]
  );
  const sorted = useMemo(
    () => [...clusters].sort((a, b) => b.count - a.count),
    [clusters]
  );

  const openCluster = (tag: string) => {
    dispatch(toggleFilterTag(tag));
    navigate(`/?${searchParams}`);
  };

  return (
    <div className="flex flex-col h-full p-4 bg-main text-app">
      <h1 className="text-2xl font-bold mb-4">Clusters</h1>
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-subtle bg-panel sticky top-0">
              <th className="px-3 py-2 text-left text-secondary font-semibold">Service</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Cluster</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Flows</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Flag out</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Flag in</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Template</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Tag</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((cluster) => (
              <tr
                key={cluster.tag}
                className="border-b border-subtle hover:bg-gray-500/10 cursor-pointer"
                onClick={() => openCluster(cluster.tag)}
              >
                <td className="px-3 py-2 font-medium">{cluster.service}</td>
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
                <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                  <Tag tag={cluster.tag} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
