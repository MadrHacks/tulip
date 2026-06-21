import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";
import { useGetChainsQuery } from "../api";
import { Tag } from "../components/Tag";

const stepLabel = (clusterId: string) =>
  clusterId.startsWith("cluster:") ? clusterId.slice("cluster:".length) : clusterId;

export function ChainsView() {
  const { data: chains = [] } = useGetChainsQuery();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const sorted = useMemo(
    () => [...chains].sort((a, b) => b.count - a.count),
    [chains]
  );

  const openChain = (tag: string) => {
    dispatch(toggleFilterTag(tag));
    navigate(`/?${searchParams}`);
  };

  return (
    <div className="flex flex-col h-full p-4 bg-main text-app">
      <h1 className="text-2xl font-bold mb-4">Chains</h1>
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-subtle bg-panel sticky top-0">
              <th className="px-3 py-2 text-left text-secondary font-semibold">Chain</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Steps</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Links</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Seen</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Runnable</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Tag</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((chain) => (
              <tr
                key={chain.tag}
                className="border-b border-subtle hover:bg-gray-500/10 cursor-pointer"
                onClick={() => openChain(chain.tag)}
              >
                <td className="px-3 py-2 font-mono text-xs">{chain.id}</td>
                <td className="px-3 py-2 font-mono text-xs">
                  {chain.steps.map((step, i) => (
                    <span key={i}>
                      {i > 0 && <span className="text-secondary"> → </span>}
                      {stepLabel(step)}
                    </span>
                  ))}
                </td>
                <td className="px-3 py-2 text-center">{chain.links}</td>
                <td className="px-3 py-2 text-center">{chain.count}</td>
                <td className="px-3 py-2 text-center">
                  {chain.runnable && (
                    <span className="inline-block px-2 py-0.5 rounded bg-blue-500/20 text-blue-600 dark:text-blue-400">
                      ✓
                    </span>
                  )}
                </td>
                <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                  <Tag tag={chain.tag} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
