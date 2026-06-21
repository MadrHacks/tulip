import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";
import { useGetChainsQuery, useGetChainBodyQuery } from "../api";
import { Chain } from "../types";
import { Tag } from "../components/Tag";

const stepLabel = (clusterId: string) =>
  clusterId.startsWith("cluster:") ? clusterId.slice("cluster:".length) : clusterId;

function ChainDetail({ chainId }: { chainId: number }) {
  const { data, isFetching } = useGetChainBodyQuery(chainId);

  if (isFetching) {
    return <div className="px-6 py-3 text-secondary">Loading…</div>;
  }
  if (!data) {
    return <div className="px-6 py-3 text-secondary">No detail.</div>;
  }
  if (!data.plan) {
    return (
      <div className="px-6 py-3 text-secondary">
        Not yet runnable — the pattern is known but at least one step template or
        link locator is still missing.
      </div>
    );
  }

  return (
    <div className="px-6 py-3 bg-panel/50 space-y-3">
      <div>
        <div className="text-secondary font-semibold mb-1">Steps</div>
        <ol className="list-decimal list-inside font-mono text-xs space-y-0.5">
          {data.plan.steps.map((step, i) => (
            <li key={i}>
              {step.service}:{step.port}
              {step.template.slots && step.template.slots.length > 0 && (
                <span className="text-secondary">
                  {" "}
                  [{step.template.slots.map((s) => s.type).join(", ")}]
                </span>
              )}
            </li>
          ))}
        </ol>
      </div>
      <div>
        <div className="text-secondary font-semibold mb-1">Links</div>
        <ul className="font-mono text-xs space-y-0.5">
          {data.plan.links.map((link, i) => (
            <li key={i}>
              step {link.producer_step} <span className="text-secondary">→</span>{" "}
              step {link.consumer_step}, inject slot {link.inject_slot}:{" "}
              <span className="text-blue-600 dark:text-blue-400">{link.extract}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function ChainRow({ chain, onOpen }: { chain: Chain; onOpen: (tag: string) => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr className="border-b border-subtle hover:bg-gray-500/10">
        <td className="px-3 py-2 text-center">
          <button
            className="text-secondary hover:text-app w-5"
            onClick={() => setExpanded((v) => !v)}
            title={expanded ? "Collapse" : "Expand"}
          >
            {expanded ? "▾" : "▸"}
          </button>
        </td>
        <td className="px-3 py-2 font-mono text-xs">{chain.id}</td>
        <td
          className="px-3 py-2 font-mono text-xs cursor-pointer"
          onClick={() => onOpen(chain.tag)}
        >
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
        <td className="px-3 py-2">
          <Tag tag={chain.tag} />
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-subtle">
          <td colSpan={7}>
            <ChainDetail chainId={chain.id} />
          </td>
        </tr>
      )}
    </>
  );
}

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
              <th className="px-3 py-2 w-8"></th>
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
              <ChainRow key={chain.tag} chain={chain} onOpen={openChain} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
