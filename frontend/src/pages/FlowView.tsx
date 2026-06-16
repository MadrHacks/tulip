import { useSearchParams, Link, useParams, useNavigate } from "react-router-dom";
import React, { ChangeEvent, useDeferredValue, useEffect, useState } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { FlowData, FullFlow } from "../types";
import { Buffer } from "buffer";
import {
  TEXT_FILTER_KEY,
  MAX_LENGTH_FOR_HIGHLIGHT,
  API_BASE_PATH,
  REPR_ID_KEY,
  FIRST_DIFF_KEY,
  SECOND_DIFF_KEY,
} from "../const";
import {
  ArrowCircleLeftIcon,
  ArrowCircleRightIcon,
  ArrowCircleUpIcon,
  ArrowCircleDownIcon,
  DownloadIcon,
  LightningBoltIcon,
} from "@heroicons/react/solid";
import { format } from "date-fns";

import { hexy } from "hexy";
import { useCopy } from "../hooks/useCopy";
import { RadioGroup } from "../components/RadioGroup";
import {
  useGetFlowQuery,
  useGetServicesQuery,
  useLazyToFullPythonRequestQuery,
  useLazyToPwnToolsQuery,
  useToSinglePythonRequestQuery,
  useGetFlagRegexQuery,
} from "../api";
import { getTickStuff } from "../tick";
import { toggleFilterFuzzyHashes, toggleFilterTag } from "../store/filter";
import { useAppDispatch, useAppSelector } from "../store";
import escapeStringRegexp from "escape-string-regexp";

const SECONDARY_NAVBAR_HEIGHT = 50;

function CopyButton({ copyText }: { copyText?: string }) {
  const { statusText, copy, copyState } = useCopy({
    getText: async () => copyText ?? "",
  });
  return (
    <>
      {copyText && (
        <button
          className="p-2 text-sm text-primary-500"
          onClick={copy}
          disabled={!copyText}
        >
          {statusText}
        </button>
      )}
    </>
  );
}

function FlowContainer({
  copyText,
  children,
}: {
  copyText?: string;
  children: React.ReactNode;
}) {
  return (
    <div className=" pb-5 flex flex-col">
      <div className="ml-auto">
        <CopyButton copyText={copyText}></CopyButton>
      </div>
      <pre className="p-5 overflow-auto">{children}</pre>
    </div>
  );
}

function HexFlow({ flow }: { flow: FlowData }) {
  const hex = hexy(Buffer.from(flow.b64, "base64"), { format: "twos" });
  return <FlowContainer copyText={hex}>{hex}</FlowContainer>;
}
function highlightText(
  flowText: string,
  search_string: string,
  flag_string: string,
  flagids: string[] = []
) {
  const flagidList = flagids.filter((f) => f !== "");
  if (
    flowText.length > MAX_LENGTH_FOR_HIGHLIGHT ||
    (flag_string === "" && search_string === "" && flagidList.length === 0)
  ) {
    return flowText;
  }
  try {
    const searchClasses = "bg-orange-200 dark:bg-orange-800 dark:text-orange-100 rounded-sm";
    const flagClasses = "bg-red-200 dark:bg-red-800 dark:text-red-100 rounded-sm";
    const flagidClasses = "bg-purple-200 dark:bg-purple-800 dark:text-purple-100 rounded-sm";

    const flagidPattern = [...flagidList]
      .sort((a, b) => b.length - a.length)
      .map(escapeStringRegexp)
      .join("|");

    const highlighters: { regex: RegExp; className: string; priority: number }[] = [];
    if (flag_string !== "")
      highlighters.push({ regex: new RegExp(flag_string, "g"), className: flagClasses, priority: 3 });
    if (flagidPattern !== "")
      highlighters.push({ regex: new RegExp(flagidPattern, "g"), className: flagidClasses, priority: 2 });
    if (search_string !== "")
      highlighters.push({ regex: new RegExp(search_string, "gi"), className: searchClasses, priority: 1 });

    type Match = { start: number; end: number; className: string; priority: number };
    const matches: Match[] = [];
    for (const h of highlighters) {
      for (const m of flowText.matchAll(h.regex)) {
        if (m[0].length === 0) continue;
        // @ts-ignore
        const start: number = m.index;
        matches.push({ start, end: start + m[0].length, className: h.className, priority: h.priority });
      }
    }

    matches.sort((a, b) => a.start - b.start || b.priority - a.priority);

    let parts = [];
    let cursor = 0;
    for (const match of matches) {
      if (match.start < cursor) continue;
      if (match.start > cursor) {
        parts.push(<span key={cursor}>{flowText.slice(cursor, match.start)}</span>);
      }
      parts.push(
        <span key={"m" + match.start} className={match.className}>
          {flowText.slice(match.start, match.end)}
        </span>
      );
      cursor = match.end;
    }
    if (cursor < flowText.length) {
      parts.push(<span key={cursor}>{flowText.slice(cursor)}</span>);
    }

    return <span>{parts}</span>;
  } catch (error) {
    console.log(error);
    return flowText;
  }
}

function TextFlow({ flow, flagids }: { flow: FlowData; flagids: string[] }) {
  let [searchParams] = useSearchParams();
  const text_filter = searchParams.get(TEXT_FILTER_KEY);
  const { data: flag_regex } = useGetFlagRegexQuery();
  const text = highlightText(flow.data, text_filter ?? "", flag_regex ?? "", flagids);

  return <FlowContainer copyText={flow.data}>{text}</FlowContainer>;
}

function WebFlow({ flow }: { flow: FlowData }) {
  const data = flow.data;
  const [header, ...rest] = data.split("\r\n\r\n");
  const http_content = rest.join("\r\n\r\n");

  const Hack = "iframe" as any;
  return (
    <FlowContainer>
      <pre>{header}</pre>
      <div className="border border-slate-200 dark:border-slate-800 rounded-lg">
        <Hack
          srcDoc={http_content}
          sandbox=""
          height={300}
          csp="default-src none" // there is a warning here but it actually works, not supported in firefox though :(
        ></Hack>
      </div>
    </FlowContainer>
  );
}

function PythonRequestFlow({
  full_flow,
  flow,
  item_index,
}: {
  full_flow: FullFlow;
  flow: FlowData;
  item_index: number,
}) {
  const { data } = useToSinglePythonRequestQuery({
    body: flow.b64,
    id: full_flow.id,
    item_index,
    tokenize: true,
  });

  return <FlowContainer copyText={data}>{data}</FlowContainer>;
}

interface FlowProps {
  full_flow: FullFlow;
  flow: FlowData;
  flow_item_index: number;
  delta_time: number;
  id: string;
}

function detectType(flow: FlowData) {
  const firstLine = flow.data.split("\n")[0];
  if (firstLine.includes("HTTP")) {
    return "Web";
  }

  return "Plain";
}

function getFlowBody(flow: FlowData, flowType: string) {
  if (flowType == "Web") {
    const contentType = flow.data.match(/Content-Type: ([^\s;]+)/im)?.[1];
    if (contentType) {
      const body = Buffer.from(flow.b64, "base64").subarray(flow.data.indexOf("\r\n\r\n") + 4);
      return [contentType, body]
    }
  }
  return null
}

function Flow({ full_flow, flow, flow_item_index, delta_time, id }: FlowProps) {
  const formatted_time = format(new Date(flow.time), "HH:mm:ss:SSS");
  const displayOptions = flow.from === "s"
    ? ["Plain", "Hex", "Web"]
    : ["Plain", "Hex", "PythonRequest"];

  // Basic type detection, currently unused
  const [displayOption, setDisplayOption] = useState("Plain");

  const flowType = detectType(flow);
  const flowBody = getFlowBody(flow, flowType);

  return (
    <div className="text-mono" id={id}>
      <div
        className="toolbar-sticky"
        style={{ top: SECONDARY_NAVBAR_HEIGHT }}
      >
        <div className="flex items-center h-6">
          <div className="w-8 px-2">
            {flow.from === "s" ? (
              <ArrowCircleLeftIcon className="fill-green-700" />
            ) : (
              <ArrowCircleRightIcon className="fill-red-700" />
            )}
          </div>
          <div style={{ width: 200 }}>
            {formatted_time}
            <span className="text-gray-400 pl-3">{delta_time}ms</span>
          </div>
          <button
            className="btn-secondary"
            onClick={async () => {
              window.open(
                "https://gchq.github.io/CyberChef/#input=" +
                encodeURIComponent(flow.b64)
              );
            }}
          >
            Open in CC
          </button>
          {flowType == "Web" && flowBody && (
            <button
              className="btn-secondary ml-2"
              onClick={async () => {
                window.open(
                  "https://gchq.github.io/CyberChef/#input=" +
                  encodeURIComponent(flowBody[1].toString("base64"))
                );
              }}
            >
              Open body in CC
            </button>
          )}
          <button
            className="btn-secondary ml-2"
            onClick={async () => {
              const blob = new Blob([Buffer.from(flow.b64, "base64")], {
                type: "application/octet-stream",
              });
              const url = window.URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.style.display = "none";
              a.href = url;
              a.download = "tulip-dl-" + id + ".dat";
              document.body.appendChild(a);
              a.click();
              window.URL.revokeObjectURL(url);
              a.remove();
            }}
          >
            Download
          </button>
          {flowType == "Web" && flowBody && (
            <button
              className="btn-secondary ml-2"
              onClick={async () => {
                const blob = new Blob([flowBody[1]], {
                  type: flowBody[0].toString(),
                });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.style.display = "none";
                a.href = url;
                a.download = "tulip-dl-" + id + ".dat";
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
              }}
            >
              Download body
            </button>
          )}
          <RadioGroup
            options={displayOptions}
            value={displayOption}
            onChange={setDisplayOption}
            className="flex gap-2 text-gray-800 text-sm mr-4 ml-auto"
          />
        </div>
      </div>
      <div
        className={
          flow.from === "s"
            ? "border-l-8 border-green-300 dark:border-green-700"
            : "border-l-8 border-red-300 dark:border-red-800"
        }
      >
        {displayOption === "Hex" && <HexFlow flow={flow}></HexFlow>}
        {displayOption === "Plain" && <TextFlow flow={flow} flagids={full_flow.flagids ?? []}></TextFlow>}
        {displayOption === "Web" && <WebFlow flow={flow}></WebFlow>}
        {displayOption === "PythonRequest" && (
          <PythonRequestFlow
            flow={flow}
            full_flow={full_flow}
            item_index={flow_item_index}
          ></PythonRequestFlow>
        )}
      </div>
    </div>
  );
}

// Helper function to format the IP for display. If the IP contains ":",
// assume it is an ipv6 address and surround it in square brackets
function formatIP(ip: string) {
  return ip.includes(":") ? `[${ip}]` : ip;
}

function FlowOverview({ flow }: { flow: FullFlow }) {
  let [searchParams, setSearchParams] = useSearchParams();
  const dispatch = useAppDispatch();
  const { unixTimeToTick } = getTickStuff();
  const { data: services } = useGetServicesQuery();
  const service = services?.find((s) => s.ip === flow.dst_ip && s.port === flow.dst_port)?.name ?? "unknown";
  return (
    <div>
      {flow.signatures?.length > 0 ? (
        <div className="bg-primary-200 dark:bg-primary-900 border-l-[4px] border-primary-400 dark:border-primary-500 p-2 dark:text-primary-100">
          <div className="font-extrabold">Suricata</div>
          <div className="pl-2">
            {flow.signatures.map((sig) => {
              return (
                <div className="py-1">
                  <div className="flex">
                    <div>Message:&nbsp;</div>
                    <div className="font-bold">{sig.message}</div>
                  </div>
                  <div className="flex">
                    <div>Rule ID:&nbsp;</div>
                    <div className="font-bold">{sig.id}</div>
                  </div>
                  <div className="flex">
                    <div>Action taken:&nbsp;</div>
                    <div
                      className={
                        sig.action === "blocked"
                          ? "font-bold text-red-800"
                          : "font-bold text-green-800"
                      }
                    >
                      {sig.action}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : undefined}
      <div className="bg-slate-100 dark:bg-slate-900 border-l-[4px] border-slate-400 dark:border-slate-700 p-2 dark:text-slate-100">
        <div className="font-extrabold">Meta</div>
        <div className="pl-2">
          <div>
            Source:&nbsp;
            <a className="font-bold" href={`${API_BASE_PATH}/download/?file=${flow.filename}`}>
              {flow.filename}
              <DownloadIcon className="inline-flex items-baseline w-5 h-5" />
            </a>
          </div>
          <div>
            Tags:&nbsp;
            <span className="font-bold">
              [{flow.tags.map((tag, i) => (
                  <span>
                    {i > 0 ? ', ' : ''}
                    <a className="font-bold cursor-pointer"
                       onClick={() => dispatch(toggleFilterTag(tag))}>
                      {tag}
                    </a>
                  </span>
                ))}]
            </span>
          </div>
          <div>
            Tick:&nbsp;
            <span className="font-bold">{unixTimeToTick(flow.time)}</span>
          </div>
          <div>
            Service:&nbsp;
            <span className="font-bold">{service}</span>
          </div>
          {flow.flags?.length > 0 && (
            <div>
              Flags:&nbsp;
              <span className="font-bold">
                [{flow.flags?.map((query, i) => (
                  <span>
                    {i > 0 ? ", " : ""}
                    <button className="font-bold"
                      onClick={() => {
                        searchParams.set(TEXT_FILTER_KEY, escapeStringRegexp(query));
                        setSearchParams(searchParams);
                      }}
                    >
                      {query}
                    </button>
                  </span>
                ))}]
              </span>
            </div>
          )}
          {flow.flagids?.length > 0 && (
            <div>
              Flagids:&nbsp;
              <span className="font-bold">
                [{flow.flagids?.map((query, i) => (
                  <span>
                    {i > 0 ? ", " : ""}
                    <button className="font-bold"
                      onClick={() => {
                        searchParams.set(TEXT_FILTER_KEY, escapeStringRegexp(query));
                        setSearchParams(searchParams);
                      }}
                    >
                      {query}
                    </button>
                  </span>
                ))}]
              </span>
            </div>
          )}
          <div>
            Source - Target (Duration):&nbsp;
            <div className="inline-flex items-center gap-1">
              <div>
                <span>{formatIP(flow.src_ip)}</span>:
                <span className="font-bold">{flow.src_port}</span>
              </div>
              <span>-</span>
              <div>
                <span>{formatIP(flow.dst_ip)}</span>:
                <span className="font-bold">{flow.dst_port}</span>
              </div>
              <span className="italic">({flow.duration} ms)</span>
            </div>
          </div>
          <div>Nilsimsa hash:&nbsp;
            <button className="font-bold"
              onClick={() => dispatch(toggleFilterFuzzyHashes([flow.fuzzyhash, flow.id]))}>
              {flow.fuzzyhash}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function FlowView() {
  let [searchParams, setSearchParams] = useSearchParams();
  const params = useParams();
  const navigate = useNavigate();

  const id = params.id;

  const [reprId, setReprId] = useState(parseInt(searchParams.get(REPR_ID_KEY) ?? "0"));

  const { data: flow, isError, isLoading } = useGetFlowQuery(id!, { skip: id === undefined });

  const [triggerPwnToolsQuery] = useLazyToPwnToolsQuery();
  const [triggerFullPythonRequestQuery] = useLazyToFullPythonRequestQuery();

  async function copyAsPwn() {
    if (flow?.id) {
      const { data } = await triggerPwnToolsQuery(flow?.id);
      console.log(data);
      return data || "";
    }
    return "";
  }

  const { statusText: pwnCopyStatusText, copy: copyPwn } = useCopy({
    getText: copyAsPwn,
    copyStateToText: {
      copied: "Copied",
      default: "Copy as pwntools",
      failed: "Failed",
      copying: "Generating payload",
    },
  });

  async function copyAsRequests() {
    if (flow?.id) {
      const { data } = await triggerFullPythonRequestQuery(flow?.id);
      return data || "";
    }
    return "";
  }

  const { statusText: requestsCopyStatusText, copy: copyRequests } = useCopy({
    getText: copyAsRequests,
    copyStateToText: {
      copied: "Copied",
      default: "Copy as requests",
      failed: "Failed",
      copying: "Generating payload",
    },
  });

  // TODO: account for user scrolling - update currentFlow accordingly
  const [currentFlow, setCurrentFlow] = useState<number>(-1);

  useHotkeys("h", () => {
    // we do this for the scroll to top
    if (currentFlow === 0) {
      document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true)
    }
    setCurrentFlow(fi => Math.max(0, fi - 1))
  }, [currentFlow]);
  useHotkeys("l", () => {
    if (currentFlow === (flow?.flow[reprId]?.flow?.length ?? 1) - 1) {
      document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true)
    }
    setCurrentFlow(fi => Math.min((flow?.flow[reprId]?.flow?.length ?? 1) - 1, fi + 1))
  }, [currentFlow, flow?.flow[reprId]?.flow?.length, reprId]);

  useEffect(
    () => {
      if (currentFlow < 0) {
        return
      }
      document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true)
    },
    [currentFlow]
  )

  useHotkeys("m", () => {
    setReprId(ri => (ri + 1) % (flow?.flow.length ?? 1))
  }, [reprId, flow?.flow.length]);

  // when the reprId changes, we update the url
  useEffect(
    () => {
      if (reprId === 0) {
        searchParams.delete(REPR_ID_KEY)
        setSearchParams(searchParams)
        return
      }
      searchParams.set(REPR_ID_KEY, reprId.toString());
      setSearchParams(searchParams)
    },
    [reprId]
  )

  // if the flow doesn't have the representation we're looking for, we fallback to raw
  useEffect(
    () => {
      if (flow?.flow.length == undefined || flow?.flow.length === 0) {
        return
      }
      if ((flow?.flow.length - 1) < reprId) {
        setReprId(0)
      }
    },
    [flow?.flow.length]
  )

  if (isError) {
    return <div>Error while fetching flow</div>;
  }

  if (isLoading || flow == undefined) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <div
        className="bg-panel border-b border-subtle sticky top-0 flex items-center text-sm p-0"
        style={{ height: 51, zIndex: 100 }}
      >
        {(flow?.child_id != null || flow?.parent_id != null) ? (
          <div className="flex align-middle p-2 gap-3">
            <button
              className="btn-primary"
              key={"parent" + flow.parent_id}
              disabled={flow?.parent_id === null}
              onMouseDown={(e) => {
                if (e.button === 1) { // handle opening in new tab
                  window.open(`/flow/${flow.parent_id}?${searchParams}`, "_blank")
                } else if (e.button === 0) {
                  navigate(`/flow/${flow.parent_id}?${searchParams}`)
                }
              }}
            >
              <ArrowCircleUpIcon className="inline-flex items-baseline w-5 h-5"></ArrowCircleUpIcon> Parent
            </button>
            <button
              className="btn-primary"
              key={"child" + flow.child_id}
              disabled={flow?.child_id === null}
              onMouseDown={(e) => {
                if (e.button === 1) { // handle opening in new tab
                  window.open(`/flow/${flow.child_id}?${searchParams}`, "_blank")
                } else if (e.button === 0) {
                  navigate(`/flow/${flow.child_id}?${searchParams}`)
                }
              }}
            >
              <ArrowCircleDownIcon className="inline-flex items-baseline w-5 h-5"></ArrowCircleDownIcon> Child
            </button>
          </div>
        ) : undefined}
        <div className="flex align-middle p-2 gap-3 ml-auto">
          <p className="my-auto">Decoders <abbr title={"Number of decoders available for this flow: " + flow?.flow.length}>({flow?.flow.length})</abbr>:</p>
          <select
            id="repr-select"
            value={reprId}
            className="input-default"
            onChange={(e) => {
              const target = e.target as HTMLSelectElement;
              const newreprid = parseInt(target.value);
              setReprId(newreprid);
            }}
          >
            {flow?.flow.map((e, i) => <option key={id + "reprselect" + i} value={i}>{e["type"]}</option>)}
          </select>
          {reprId > 0 ? <button
            className="btn-secondary"
            title="Diff this representation with the base"
            onClick={(e) => {
              searchParams.set(FIRST_DIFF_KEY, `${id}`);
              searchParams.set(SECOND_DIFF_KEY, `${id}:${reprId}`);
              navigate(`/diff?${searchParams}`, { replace: true });
            }}
          >
            <LightningBoltIcon className="h-5 w-5"></LightningBoltIcon>
          </button> : undefined}
          <button
            className="btn-secondary"
            onClick={copyPwn}
          >
            {pwnCopyStatusText}
          </button>

          <button
            className="btn-secondary"
            onClick={copyRequests}
          >
            {requestsCopyStatusText}
          </button>
        </div>
      </div>

      {flow ? <FlowOverview flow={flow}></FlowOverview> : undefined}
      {flow?.flow[(reprId < flow?.flow.length) ? reprId : 0].flow.map((flow_data, i, a) => {
        const delta_time = a[i].time - (a[i - 1]?.time ?? a[i].time);
        return (
          <Flow
            flow={flow_data}
            flow_item_index={i}
            delta_time={delta_time}
            full_flow={flow}
            key={flow.id + "-" + i}
            id={flow.id + "-" + i}
          ></Flow>
        );
      })}
    </div>
  );
}
