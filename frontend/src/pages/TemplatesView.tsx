import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";
import { useGetTemplatesQuery, useLazyGetTemplateScaffoldQuery } from "../api";
import { Tag } from "../components/Tag";

export function TemplatesView() {
  const { data: templates = [] } = useGetTemplatesQuery();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const [getScaffold] = useLazyGetTemplateScaffoldQuery();

  const copyScaffold = async (service: string, clusterId: number) => {
    const { data } = await getScaffold({ service, clusterId });
    if (data) {
      await navigator.clipboard.writeText(data);
    }
  };

  const sorted = useMemo(
    () => [...templates].sort((a, b) => {
      if (a.service !== b.service) return a.service.localeCompare(b.service);
      return a.cluster_id - b.cluster_id;
    }),
    [templates]
  );

  const openTemplate = (tag: string) => {
    dispatch(toggleFilterTag(tag));
    navigate(`/?${searchParams}`);
  };

  const slotColor = (slot: string): string => {
    const slotTypeColors: Record<string, string> = {
      flagid: "text-blue-600 dark:text-blue-400 bg-blue-500/20",
      random: "text-purple-600 dark:text-purple-400 bg-purple-500/20",
      const: "text-green-600 dark:text-green-400 bg-green-500/20",
      flag: "text-orange-600 dark:text-orange-400 bg-orange-500/20",
    };
    return slotTypeColors[slot] || "text-gray-600 dark:text-gray-400 bg-gray-500/20";
  };

  return (
    <div className="flex flex-col h-full p-4 bg-main text-app">
      <h1 className="text-2xl font-bold mb-4">Templates</h1>
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-subtle bg-panel sticky top-0">
              <th className="px-3 py-2 text-left text-secondary font-semibold">Service</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Cluster</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Slots</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Version</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Scaffold</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Tag</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((template) => (
              <tr
                key={`${template.service}-${template.cluster_id}`}
                className="border-b border-subtle hover:bg-gray-500/10 cursor-pointer"
                onClick={() => openTemplate(template.tag)}
              >
                <td className="px-3 py-2 font-medium">{template.service}</td>
                <td className="px-3 py-2 font-mono text-xs">{template.cluster_id}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">
                    {template.slots.map((slot) => (
                      <span
                        key={slot}
                        className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${slotColor(slot)}`}
                      >
                        {slot}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2 text-center font-mono">{template.version}</td>
                <td className="px-3 py-2 text-center" onClick={(e) => e.stopPropagation()}>
                  <button
                    onClick={() => copyScaffold(template.service, template.cluster_id)}
                    className="px-2 py-1 text-xs font-medium rounded bg-blue-500/20 text-blue-600 dark:text-blue-400 hover:bg-blue-500/30"
                  >
                    Copy
                  </button>
                </td>
                <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                  <Tag tag={template.tag} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}