import { Fragment, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";
import { useGetShapesQuery } from "../api";
import { Shape } from "../types";
import { Tag } from "../components/Tag";

// Neutral view over mined SHAPES. A shape is only a recurring request pattern;
// nothing here is an attack verdict. We surface OBSERVED SIGNALS — flags seen in
// responses (candidate-exfil, since the checker leaks flags too), stored flags,
// actors, and a representative response size. "Exploit" status is earned later
// via nop-proof or a human label, never asserted on this page.
export function ShapesView() {
  const { data: shapes = [] } = useGetShapesQuery();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  // Group shapes under their service; within a service the shapes leaking the
  // most flags-in-response come first (the strongest candidate-exfil signal),
  // then the ones with the most members.
  const grouped = useMemo(() => {
    const byService = new Map<string, Shape[]>();
    for (const s of shapes) {
      const arr = byService.get(s.service);
      if (arr) arr.push(s);
      else byService.set(s.service, [s]);
    }
    return [...byService.entries()]
      .map(([service, ss]) => ({
        service,
        flagPresent: ss.reduce((sum, s) => sum + s.flag_present, 0),
        shapes: [...ss].sort(
          (a, b) => b.flag_present - a.flag_present || b.members - a.members
        ),
      }))
      .sort(
        (a, b) =>
          b.flagPresent - a.flagPresent || a.service.localeCompare(b.service)
      );
  }, [shapes]);

  const openShape = (tag: string) => {
    dispatch(toggleFilterTag(tag));
    navigate(`/?${searchParams}`);
  };

  const humanSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="flex flex-col h-full p-4 bg-main text-app">
      <h1 className="text-2xl font-bold mb-1">Shapes</h1>
      <p className="text-xs text-secondary mb-4 max-w-3xl">
        A shape is a <span className="font-semibold">neutral recurring request
        pattern</span>, not an attack. Everything below is an{" "}
        <span className="font-semibold">observed signal</span>: "flags in
        response" is a candidate-exfil hint (the checker leaks flags too, so it
        is not proof), "stores flag" means members persisted a flag. "Exploit"
        status is earned later via nop-proof or a human label — never asserted
        here.
      </p>
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-subtle bg-panel sticky top-0">
              <th className="px-3 py-2 text-left text-secondary font-semibold">Shape</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Template</th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">Members</th>
              <th
                className="px-3 py-2 text-center text-secondary font-semibold"
                title="Members whose response contained a flag — a candidate-exfil signal, not proof of an attack (the checker also leaks flags)."
              >
                Flags in response
              </th>
              <th
                className="px-3 py-2 text-center text-secondary font-semibold"
                title="Members that stored a flag (flag-in signal)."
              >
                Stores flag
              </th>
              <th className="px-3 py-2 text-center text-secondary font-semibold">~Size</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Actors</th>
              <th className="px-3 py-2 text-left text-secondary font-semibold">Tag</th>
            </tr>
          </thead>
          <tbody>
            {grouped.map((group) => (
              <Fragment key={group.service}>
                <tr className="border-b border-subtle bg-gray-500/10">
                  <td colSpan={8} className="px-3 py-2">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="font-semibold">{group.service}</span>
                      <span className="text-xs text-secondary">
                        {group.shapes.length} shape{group.shapes.length === 1 ? "" : "s"}
                      </span>
                    </div>
                  </td>
                </tr>
                {group.shapes.map((shape) => {
                  const isOpen = expanded[shape.tag];
                  const actors = Object.entries(shape.actors);
                  return (
                    <tr
                      key={shape.tag}
                      className="border-b border-subtle hover:bg-gray-500/10 cursor-pointer align-top"
                      onClick={() => openShape(shape.tag)}
                    >
                      <td className="px-3 py-2 font-mono text-xs">{shape.shape_id}</td>
                      <td className="px-3 py-2 max-w-md">
                        <code
                          className={`font-mono text-xs text-secondary block ${
                            isOpen ? "whitespace-pre-wrap break-all" : "truncate"
                          }`}
                          title="Click to expand/collapse"
                          onClick={(e) => {
                            e.stopPropagation();
                            setExpanded((prev) => ({
                              ...prev,
                              [shape.tag]: !prev[shape.tag],
                            }));
                          }}
                        >
                          {shape.template}
                        </code>
                      </td>
                      <td className="px-3 py-2 text-center">{shape.members}</td>
                      <td className="px-3 py-2 text-center">
                        {shape.flag_present > 0 && (
                          <span
                            className="inline-block px-2 py-0.5 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400"
                            title="Candidate-exfil signal, not an attack verdict."
                          >
                            {shape.flag_present}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center">
                        {shape.flag_in > 0 && (
                          <span className="inline-block px-2 py-0.5 rounded bg-green-500/20 text-green-600 dark:text-green-400">
                            {shape.flag_in}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center text-xs text-secondary whitespace-nowrap">
                        {humanSize(shape.size)}
                      </td>
                      <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {actors.length === 0 && (
                            <span className="text-xs text-secondary">—</span>
                          )}
                          {actors.map(([ua, count]) => (
                            <span
                              key={ua}
                              className="inline-block px-2 py-0.5 rounded bg-gray-500/15 text-secondary text-xs font-mono truncate max-w-[10rem]"
                              title={`${ua} (${count})`}
                            >
                              {ua} · {count}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                        <Tag tag={shape.tag} />
                      </td>
                    </tr>
                  );
                })}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
